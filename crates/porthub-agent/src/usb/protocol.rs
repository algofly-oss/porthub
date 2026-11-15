//! USB/IP discovery/import framing at the Windows kernel-driver boundary.
//! Physical transfer requests remain opaque bytes in PortHub's authenticated carrier.
use anyhow::{ensure, Result};
use porthub_components::usb::{Device, valid_busid};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub(super) const DEVICE_SIZE: usize = 312;
const VERSION: u16 = 0x0111;
const IMPORT: u16 = 3;

fn cstring(bytes:&[u8])->Result<&str> {
    let end=bytes.iter().position(|b|*b==0).unwrap_or(bytes.len());
    Ok(std::str::from_utf8(&bytes[..end])?)
}
fn put(bytes:&mut [u8],text:&str)->Result<()> {
    ensure!(text.len()<bytes.len()&&!text.bytes().any(|b|b==0),"USB/IP identifier is too long");
    bytes.fill(0);bytes[..text.len()].copy_from_slice(text.as_bytes());Ok(())
}
fn header(code:u16,status:u32)->[u8;8] {
    let mut h=[0;8];h[..2].copy_from_slice(&VERSION.to_be_bytes());h[2..4].copy_from_slice(&code.to_be_bytes());h[4..].copy_from_slice(&status.to_be_bytes());h
}
pub(super) fn validate(bytes:&[u8],expected:&Device)->Result<Device> {
    ensure!(bytes.len()==DEVICE_SIZE&&expected.valid(),"Invalid USB/IP device record");
    let mut device=expected.clone();
    let busid=cstring(&bytes[256..288])?;ensure!(valid_busid(busid),"Invalid USB/IP bus ID");
    device.busid=busid.into();
    device.busnum=u32::from_be_bytes(bytes[288..292].try_into()?).try_into()?;
    device.devnum=u32::from_be_bytes(bytes[292..296].try_into()?).try_into()?;
    device.speed=u32::from_be_bytes(bytes[296..300].try_into()?);
    device.vendor=format!("{:04x}",u16::from_be_bytes(bytes[300..302].try_into()?));
    device.product=format!("{:04x}",u16::from_be_bytes(bytes[302..304].try_into()?));
    ensure!(device.valid()&&device.same_device(expected),"USB/IP device identity changed");
    Ok(device)
}
pub(super) async fn import<S:AsyncRead+AsyncWrite+Unpin>(stream:&mut S,device:&Device)->Result<(Device,Vec<u8>)> {
    ensure!(device.valid(),"Invalid USB/IP device");
    let mut request=vec![0;40];request[..8].copy_from_slice(&header(0x8000|IMPORT,0));put(&mut request[8..],&device.busid)?;
    stream.write_all(&request).await?;stream.flush().await?;
    let mut response=[0;8];stream.read_exact(&mut response).await?;
    ensure!(response==header(IMPORT,0),"Windows USB export driver rejected the selected device");
    let mut bytes=vec![0;DEVICE_SIZE];stream.read_exact(&mut bytes).await?;
    let actual=validate(&bytes,device)?;Ok((actual,bytes))
}
pub(super) async fn accept_import<S:AsyncRead+AsyncWrite+Unpin>(stream:&mut S,capability:&str,wire:&[u8],device:&Device)->Result<()> {
    validate(wire,device)?;
    ensure!((16..32).contains(&capability.len())&&capability.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'),"Invalid local USB capability");
    let mut request=[0;40];stream.read_exact(&mut request).await?;
    ensure!(request[..8]==header(0x8000|IMPORT,0),"Unsupported USB/IP kernel request");
    let selected=cstring(&request[8..])?;
    ensure!(selected==capability,"Local USB kernel capability mismatch");
    let mut reply=wire.to_vec();put(&mut reply[256..288],capability)?;
    // The Windows UDE controller exposes USB 3.0 virtual ports. Physical
    // SuperSpeedPlus devices retain their identity and use compatible USB3 URBs.
    if device.speed==6 {reply[296..300].copy_from_slice(&5u32.to_be_bytes());}
    stream.write_all(&header(IMPORT,0)).await?;stream.write_all(&reply).await?;stream.flush().await?;Ok(())
}
// Older Linux agents send the stable USB identifiers but not the optional
// descriptor fields. The kernel reads actual descriptors through control URBs.
pub(super) fn legacy_device(device:&Device)->Result<Vec<u8>> {
    ensure!(device.valid(),"Invalid legacy USB/IP device");
    let mut wire=vec![0;DEVICE_SIZE];put(&mut wire[..256],"porthub")?;put(&mut wire[256..288],&device.busid)?;
    for(offset,value)in[(288,device.busnum as u32),(292,device.devnum as u32),(296,device.speed)]{wire[offset..offset+4].copy_from_slice(&value.to_be_bytes());}
    wire[300..302].copy_from_slice(&u16::from_str_radix(&device.vendor,16)?.to_be_bytes());wire[302..304].copy_from_slice(&u16::from_str_radix(&device.product,16)?.to_be_bytes());
    wire[309..312].fill(1);validate(&wire,device)?;Ok(wire)
}
#[cfg(target_os="linux")]
pub(super) fn local_device(device:&Device)->Result<Vec<u8>> {
    use std::path::Path;
    ensure!(device.valid(),"Invalid USB/IP physical device");
    let root=Path::new("/sys/bus/usb/devices").join(&device.busid);
    let descriptor=std::fs::read(root.join("descriptors"))?;
    ensure!(descriptor.len()>=18&&descriptor[0]==18&&descriptor[1]==1,"USB device descriptor unavailable");
    let mut bytes=vec![0;DEVICE_SIZE];put(&mut bytes[..256],&format!("porthub/{}",device.busid))?;put(&mut bytes[256..288],&device.busid)?;
    for(offset,value)in[(288,device.busnum as u32),(292,device.devnum as u32),(296,device.speed)]{bytes[offset..offset+4].copy_from_slice(&value.to_be_bytes());}
    for(offset,index)in[(300,8),(302,10),(304,12)]{bytes[offset..offset+2].copy_from_slice(&u16::from_le_bytes(descriptor[index..index+2].try_into()?).to_be_bytes());}
    bytes[306..309].copy_from_slice(&descriptor[4..7]);
    bytes[309]=std::fs::read_to_string(root.join("bConfigurationValue")).ok().and_then(|s|s.trim().parse().ok()).unwrap_or(1);
    bytes[310]=descriptor[17];
    bytes[311]=std::fs::read_to_string(root.join("bNumInterfaces")).ok().and_then(|s|s.trim().parse().ok()).unwrap_or(1);
    validate(&bytes,device)?;Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture()->(Device,Vec<u8>){let d=Device{busid:"2-1".into(),vendor:"152d".into(),product:"a583".into(),serial:"fixture".into(),name:"SSD".into(),busnum:2,devnum:6,speed:6,blocked:None};let mut w=vec![0;DEVICE_SIZE];put(&mut w[256..288],&d.busid).unwrap();w[288..292].copy_from_slice(&2u32.to_be_bytes());w[292..296].copy_from_slice(&6u32.to_be_bytes());w[296..300].copy_from_slice(&6u32.to_be_bytes());w[300..302].copy_from_slice(&0x152du16.to_be_bytes());w[302..304].copy_from_slice(&0xa583u16.to_be_bytes());(d,w)}
    #[test]fn physical_identity_and_bounds_are_checked(){let(d,mut w)=fixture();assert!(validate(&w,&d).is_ok());w[300]=0;assert!(validate(&w,&d).is_err());assert!(validate(&w[..311],&d).is_err());}
    #[tokio::test]async fn local_kernel_import_is_capability_bound_and_downgrades_only_virtual_speed()->Result<()>{let(d,w)=fixture();let(mut a,mut b)=tokio::io::duplex(4096);let cap="1-0123456789012345678901234567";let source=d.clone();let task=tokio::spawn(async move{accept_import(&mut a,cap,&w,&source).await});let mut req=vec![0;40];req[..8].copy_from_slice(&header(0x8003,0));put(&mut req[8..],cap)?;b.write_all(&req).await?;let mut response=vec![0;320];b.read_exact(&mut response).await?;task.await??;ensure!(response[..8]==header(3,0));ensure!(cstring(&response[264..296])?==cap);ensure!(u32::from_be_bytes(response[304..308].try_into()?)==5);Ok(())}
}
