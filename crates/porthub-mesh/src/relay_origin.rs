//! Negotiated server-to-client origin metadata. Never accepted as an uplink
//! authority. Identity definitions are deduplicated within each bounded batch.
use anyhow::{ensure, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, sync::Arc};
pub const MAGIC: &[u8;4]=b"PHO1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub peer: String,
    pub ip: Ipv4Addr,
    pub fingerprint: String,
    pub instance: String,
    pub stamp: String,
}
impl Origin {
    pub fn validate(&self)->Result<()> {
        ensure!(!self.peer.is_empty()&&self.peer.len()<=60,"invalid relay origin peer");
        ensure!(!self.instance.is_empty()&&self.instance.len()<=256,"invalid relay origin instance");
        ensure!(!self.fingerprint.is_empty()&&self.fingerprint.len()<=256,"invalid relay origin fingerprint");
        ensure!(self.stamp.len()==32&&self.stamp.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"invalid relay origin stamp");
        Ok(())
    }
}
pub fn encode(records:&[(Arc<Origin>,Bytes)])->Result<Bytes> {
    ensure!(!records.is_empty()&&records.len()<=32,"relay origin record bound");
    let mut definitions:Vec<Arc<Origin>>=Vec::new();let mut indices=Vec::new();
    for(origin,packet)in records {
        origin.validate()?;ensure!((20..=1380).contains(&packet.len()),"relay origin packet bound");
        let index=definitions.iter().position(|old|old.as_ref()==origin.as_ref()).unwrap_or_else(||{definitions.push(origin.clone());definitions.len()-1});
        ensure!(!definitions.iter().enumerate().any(|(i,old)|i!=index&&old.stamp==origin.stamp),"duplicate relay origin stamp");
        indices.push(index as u8);
    }
    let mut bytes=MAGIC.to_vec();bytes.push(definitions.len()as u8);
    for origin in definitions {
        let mut encoded=Vec::new();encoded.push(origin.peer.len() as u8);encoded.extend_from_slice(origin.peer.as_bytes());encoded.extend_from_slice(&origin.ip.octets());
        for field in [&origin.fingerprint,&origin.instance]{encoded.extend_from_slice(&(field.len()as u16).to_be_bytes());encoded.extend_from_slice(field.as_bytes());}
        encoded.extend_from_slice(origin.stamp.as_bytes());ensure!(encoded.len()<=1024,"relay origin definition bound");
        bytes.extend_from_slice(&(encoded.len()as u16).to_be_bytes());bytes.extend_from_slice(&encoded);
    }
    bytes.push(records.len()as u8);
    for((_,packet),index)in records.iter().zip(indices){bytes.push(index);bytes.extend_from_slice(&(packet.len()as u16).to_be_bytes());bytes.extend_from_slice(packet);}
    ensure!(bytes.len()<=65536,"relay origin frame bound");Ok(bytes.into())
}
pub fn decode(frame:Bytes)->Result<Vec<(Arc<Origin>,Bytes)>> {
    ensure!(frame.len()<=65536&&frame.get(..4)==Some(MAGIC),"invalid relay origin frame");let mut at=4;
    fn byte(frame:&[u8],at:&mut usize)->Result<u8>{let x=*frame.get(*at).ok_or_else(||anyhow::anyhow!("short relay origin frame"))?;*at+=1;Ok(x)}
    fn length(frame:&[u8],at:&mut usize)->Result<usize>{Ok(u16::from_be_bytes([byte(frame,at)?,byte(frame,at)?])as usize)}
    let count=byte(&frame,&mut at)?as usize;ensure!((1..=32).contains(&count),"relay origin definition count");let mut definitions=Vec::new();
    for _ in 0..count {
        let len=length(&frame,&mut at)?;ensure!((1..=1024).contains(&len),"relay origin definition bound");
        let body=frame.get(at..at+len).ok_or_else(||anyhow::anyhow!("short relay origin definition"))?;
        let mut cursor=0;let n=byte(body,&mut cursor)?as usize;
        fn text(body:&[u8],cursor:&mut usize,n:usize)->Result<String>{let value=body.get(*cursor..*cursor+n).ok_or_else(||anyhow::anyhow!("short relay origin identity"))?;*cursor+=n;Ok(std::str::from_utf8(value)?.into())}
        let peer=text(body,&mut cursor,n)?;
        let ip=Ipv4Addr::new(byte(body,&mut cursor)?,byte(body,&mut cursor)?,byte(body,&mut cursor)?,byte(body,&mut cursor)?);
        let n=length(body,&mut cursor)?;let fingerprint=text(body,&mut cursor,n)?;
        let n=length(body,&mut cursor)?;let instance=text(body,&mut cursor,n)?;
        let stamp=text(body,&mut cursor,32)?;ensure!(cursor==body.len(),"trailing relay origin identity");
        let origin=Origin{peer,ip,fingerprint,instance,stamp};origin.validate()?;
        ensure!(!definitions.iter().any(|old:&Arc<Origin>|old.stamp==origin.stamp),"duplicate relay origin stamp");
        definitions.push(Arc::new(origin));at+=len;
    }
    let count=byte(&frame,&mut at)?as usize;ensure!((1..=32).contains(&count),"relay origin record count");let mut out=Vec::new();
    for _ in 0..count {
        let index=byte(&frame,&mut at)?as usize;let len=length(&frame,&mut at)?;ensure!((20..=1380).contains(&len)&&at+len<=frame.len(),"relay origin packet bound");
        let origin=definitions.get(index).ok_or_else(||anyhow::anyhow!("unknown relay origin index"))?.clone();
        out.push((origin,frame.slice(at..at+len)));at+=len;
    }
    ensure!(at==frame.len(),"trailing relay origin bytes");Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn origin()->Arc<Origin>{Arc::new(Origin{peer:"peer".into(),ip:"10.203.0.1".parse().unwrap(),fingerprint:"fp".into(),instance:"instance".into(),stamp:"a".repeat(32)})}
    #[test]
    fn identity_is_shared_per_definition_and_preserved_across_generation_changes(){
        let old=origin();let packet=Bytes::from(vec![1;28]);let records=vec![(old.clone(),packet.clone()),(old.clone(),packet.clone())];
        let decoded=decode(encode(&records).unwrap()).unwrap();assert!(Arc::ptr_eq(&decoded[0].0,&decoded[1].0));assert_eq!(decoded[0].0,old);assert_eq!(decoded[1].1,packet);
        let mut new=old.as_ref().clone();new.stamp="b".repeat(32);let new=Arc::new(new);let decoded=decode(encode(&[(old,packet.clone()),(new,packet)]).unwrap()).unwrap();assert_ne!(decoded[0].0.stamp,decoded[1].0.stamp);
    }
    #[test]
    fn malformed_and_unbounded_frames_fail_closed(){
        let record=(origin(),Bytes::from(vec![0;20]));let valid=encode(&[record.clone()]).unwrap();
        for len in 0..valid.len(){assert!(decode(valid.slice(..len)).is_err());}
        let mut trailing=valid.to_vec();trailing.push(0);assert!(decode(trailing.into()).is_err());
        assert!(encode(&vec![record;33]).is_err());assert!(decode(Bytes::from(vec![0;65537])).is_err());
        let mut bad=origin().as_ref().clone();bad.stamp="A".repeat(32);assert!(bad.validate().is_err());
    }
}
