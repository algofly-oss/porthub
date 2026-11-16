//! Structural baseline MJPEG validation; no camera access or pixel decoding.
use porthub_components::media::jpeg_dimensions;
pub(super) fn baseline(jpeg: &[u8]) -> bool {
    if jpeg_dimensions(jpeg) != Some((640, 480)) {
        return false;
    }
    let mut at = 2;
    let mut sof = false;
    let mut component_ids = Vec::new();
    while at + 4 <= jpeg.len() {
        if jpeg[at] != 0xff {
            return false;
        }
        while jpeg.get(at) == Some(&0xff) {
            at += 1;
        }
        let Some(&marker) = jpeg.get(at) else {
            return false;
        };
        at += 1;
        // Baseline sequential only; no abbreviated image or premature EOI.
        if matches!(marker, 0 | 0xd8 | 0xd9 | 1 | 0xd0..=0xd7) {
            return false;
        }
        let Some(bytes) = jpeg.get(at..at + 2) else {
            return false;
        };
        let length = u16::from_be_bytes(bytes.try_into().unwrap()) as usize;
        let Some(end) = at.checked_add(length) else {
            return false;
        };
        if length < 2 || end > jpeg.len() {
            return false;
        }
        if (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            if marker != 0xc0 || sof || length < 11 {
                return false;
            }
            let components = jpeg[at + 7] as usize;
            if components == 0
                || components > 4
                || length != 8 + 3 * components
                || jpeg[at + 2] != 8
            {
                return false;
            }
            for component in jpeg[at + 8..end].chunks_exact(3) {
                if component_ids.contains(&component[0])
                    || component[1] >> 4 == 0
                    || component[1] & 15 == 0
                    || component[1] >> 4 > 4
                    || component[1] & 15 > 4
                    || component[2] > 3
                {
                    return false;
                }
                component_ids.push(component[0]);
            }
            sof = true;
        }
        if marker == 0xda {
            if !sof || length < 8 {
                return false;
            }
            let components = jpeg[at + 2] as usize;
            if components == 0
                || components > 4
                || length != 6 + 2 * components
                || jpeg[end - 3..end] != [0, 63, 0]
            {
                return false;
            }
            let mut scanned = Vec::new();
            for component in jpeg[at + 3..end - 3].chunks_exact(2) {
                if !component_ids.contains(&component[0])
                    || scanned.contains(&component[0])
                    || component[1] >> 4 > 3
                    || component[1] & 15 > 3
                {
                    return false;
                }
                scanned.push(component[0]);
            }
            if scanned.len() != component_ids.len() {
                return false;
            }
            // Scan entropy without decoding pixels: byte stuffing and restart
            // markers are allowed; require nonempty scan and exact final EOI.
            let mut scan = end;
            let mut entropy = false;
            while scan < jpeg.len() {
                if jpeg[scan] != 0xff {
                    entropy = true;
                    scan += 1;
                    continue;
                }
                scan += 1;
                while jpeg.get(scan) == Some(&0xff) {
                    scan += 1;
                }
                let Some(&next) = jpeg.get(scan) else {
                    return false;
                };
                scan += 1;
                match next {
                    0 => entropy = true,
                    0xd0..=0xd7 => {}
                    0xd9 => return entropy && scan == jpeg.len(),
                    _ => return false,
                }
            }
            return false;
        }
        at = end;
    }
    false
}
