//! Windows built-in CPU JPEG encoder, bounded to a fixed private memory stream.
use anyhow::{ensure, Context, Result};
use windows::{
    core::Interface,
    Win32::{
        Graphics::Imaging::*,
        System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER},
    },
};
const MAX: usize = porthub_components::media::MAX_VIDEO_FRAME;
pub struct Encoder(IWICImagingFactory);
impl Encoder {
    pub fn new() -> Result<Self> {
        Ok(Self(unsafe {
            CoCreateInstance(&CLSID_WICImagingFactory, None, CLSCTX_INPROC_SERVER)
        }?))
    }
    pub fn encode(&self, bgr: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            bgr.len() == 640 * 480 * 3,
            "JPEG encoder requires fixed 640x480 BGR"
        );
        let mut output = vec![0u8; MAX];
        // All COM references die before output is accessed or freed. The WIC
        // stream cannot grow beyond this allocation (Microsoft API contract).
        let result = (|| -> Result<()> {
            let stream = unsafe { self.0.CreateStream() }?;
            // Use the mutable allocation's raw pointer directly: the generated
            // &[u8] projection would misleadingly create a shared Rust borrow
            // although the underlying Windows memory stream writes this memory.
            unsafe {
                (stream.vtable().InitializeFromMemory)(
                    stream.as_raw(),
                    output.as_mut_ptr(),
                    MAX as u32,
                )
                .ok()
            }?;
            let encoder = unsafe {
                self.0
                    .CreateEncoder(&GUID_ContainerFormatJpeg, &GUID_VendorMicrosoft)
            }?;
            unsafe { encoder.Initialize(&stream, WICBitmapEncoderNoCache) }?;
            let (mut frame, mut options) = (None, None);
            unsafe { encoder.CreateNewFrame(&mut frame, &mut options) }?;
            let frame = frame.context("Windows JPEG frame is unavailable")?;
            unsafe { frame.Initialize(options.as_ref()) }?;
            unsafe { frame.SetSize(640, 480) }?;
            let mut pixel = GUID_WICPixelFormat24bppBGR;
            unsafe { frame.SetPixelFormat(&mut pixel) }?;
            ensure!(
                pixel == GUID_WICPixelFormat24bppBGR,
                "JPEG encoder changed the BGR format"
            );
            unsafe { frame.WritePixels(480, 640 * 3, bgr) }?;
            unsafe { frame.Commit() }?;
            unsafe { encoder.Commit() }?;
            Ok(())
        })();
        if let Err(error) = result {
            output.fill(0);
            return Err(error);
        }
        // Only one image is written to freshly zero-filled fixed memory, with
        // no caller metadata/thumbnails; final EOI bounds its encoded extent.
        let Some(end) = output
            .windows(2)
            .rposition(|p| p == [0xff, 0xd9])
            .map(|n| n + 2)
        else {
            output.fill(0);
            anyhow::bail!("Windows JPEG encoder returned no complete image")
        };
        output.truncate(end);
        Ok(output)
    }
}
