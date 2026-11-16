//! Bounded CPU-only conversion for explicitly negotiated packed/planar YUV.
//! No scaling, decoder, GPU, default camera or native device access.
use anyhow::{ensure, Result};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Nv12,
    Yuy2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Matrix {
    Bt601,
    Bt709,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Range {
    Limited,
    Full,
}
fn pixel(y: u8, u: u8, v: u8, matrix: Matrix, range: Range) -> [u8; 3] {
    let (d, e) = (u as i32 - 128, v as i32 - 128);
    let (c, scale) = match range {
        Range::Limited => ((y as i32 - 16).max(0), 298),
        Range::Full => (y as i32, 256),
    };
    let (rv, gu, gv, bu) = match (matrix, range) {
        (Matrix::Bt601, Range::Limited) => (409, 100, 208, 516),
        (Matrix::Bt709, Range::Limited) => (459, 55, 136, 541),
        (Matrix::Bt601, Range::Full) => (359, 88, 183, 454),
        (Matrix::Bt709, Range::Full) => (403, 48, 120, 475),
    };
    let clip = |x: i32| ((x + 128) >> 8).clamp(0, 255) as u8;
    [
        clip(scale * c + bu * d),
        clip(scale * c - gu * d - gv * e),
        clip(scale * c + rv * e),
    ]
}
pub fn bgr(
    bytes: &[u8],
    width: usize,
    height: usize,
    stride: usize,
    layout: Layout,
    matrix: Matrix,
    range: Range,
) -> Result<Vec<u8>> {
    ensure!(
        width > 0
            && height > 0
            && width <= 640
            && height <= 480
            && width % 2 == 0
            && height % 2 == 0,
        "Raw camera dimensions exceed fixed mode"
    );
    let minimum = match layout {
        Layout::Nv12 => width,
        Layout::Yuy2 => width * 2,
    };
    ensure!(
        stride >= minimum && stride <= 8192,
        "Invalid native YUV stride"
    );
    let y = stride
        .checked_mul(height)
        .ok_or_else(|| anyhow::anyhow!("YUV bounds overflow"))?;
    let required = match layout {
        Layout::Nv12 => y.checked_add(stride * (height / 2)),
        Layout::Yuy2 => Some(y),
    }
    .ok_or_else(|| anyhow::anyhow!("YUV bounds overflow"))?;
    ensure!(
        required <= 2 * 1024 * 1024 && bytes.len() >= required && bytes.len() <= 2 * 1024 * 1024,
        "Truncated or oversized native YUV frame"
    );
    let mut output = vec![0; width * height * 3];
    for row in 0..height {
        for col in 0..width {
            let (a, u, v) = match layout {
                Layout::Nv12 => {
                    let uv = y + (row / 2) * stride + (col & !1);
                    (bytes[row * stride + col], bytes[uv], bytes[uv + 1])
                }
                Layout::Yuy2 => {
                    let at = row * stride + (col & !1) * 2;
                    (
                        bytes[at + if col % 2 == 0 { 0 } else { 2 }],
                        bytes[at + 1],
                        bytes[at + 3],
                    )
                }
            };
            output[(row * width + col) * 3..(row * width + col + 1) * 3]
                .copy_from_slice(&pixel(a, u, v, matrix, range));
        }
    }
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_limited_black_white_and_red() {
        assert_eq!(
            pixel(16, 128, 128, Matrix::Bt601, Range::Limited),
            [0, 0, 0]
        );
        assert_eq!(
            pixel(235, 128, 128, Matrix::Bt601, Range::Limited),
            [255, 255, 255]
        );
        let red = pixel(81, 90, 240, Matrix::Bt601, Range::Limited);
        assert!(red[0] < 3 && red[1] < 3 && red[2] > 250);
        assert_eq!(pixel(0, 128, 128, Matrix::Bt709, Range::Full), [0, 0, 0]);
    }
    #[test]
    fn padded_nv12_and_yuy2_respect_plane_bounds() {
        let n = [16, 235, 99, 99, 16, 235, 99, 99, 128, 128, 99, 99];
        assert_eq!(
            bgr(&n, 2, 2, 4, Layout::Nv12, Matrix::Bt601, Range::Limited).unwrap(),
            [0, 0, 0, 255, 255, 255, 0, 0, 0, 255, 255, 255]
        );
        let y = [16, 128, 235, 128, 99, 99, 16, 128, 235, 128, 99, 99];
        assert!(bgr(&y, 2, 2, 6, Layout::Yuy2, Matrix::Bt601, Range::Limited).is_ok());
        assert!(bgr(
            &n[..8],
            2,
            2,
            4,
            Layout::Nv12,
            Matrix::Bt601,
            Range::Limited
        )
        .is_err());
        assert!(bgr(&n, 3, 2, 4, Layout::Nv12, Matrix::Bt601, Range::Limited).is_err());
    }
}
