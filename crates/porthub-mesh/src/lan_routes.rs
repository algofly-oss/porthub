//! Small validated RFC1918 prefix advertisements. Advertisements describe
//! reachability; the signed-in user's exit policy grants permission separately.
use anyhow::{ensure,Result};
use serde::{Deserialize,Serialize};
use std::{fmt,net::Ipv4Addr,str::FromStr};

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord,Serialize,Deserialize)]
#[serde(try_from="String",into="String")]
pub struct Network {
    address:Ipv4Addr,
    prefix:u8,
}
impl Network {
    pub fn from_address(address:Ipv4Addr,prefix:u8)->Result<Self> {
        ensure!((1..=32).contains(&prefix),"invalid LAN prefix length");
        let mask=u32::MAX<<(32-prefix);
        let address=Ipv4Addr::from(u32::from(address)&mask);
        let last=Ipv4Addr::from(u32::from(address)|!mask);
        ensure!(address.is_private() && last.is_private(),"LAN advertisements must stay inside a private IPv4 range");
        Ok(Self {address,prefix})
    }
    pub fn contains(self,address:Ipv4Addr)->bool {
        u32::from(address)>>(32-self.prefix)==u32::from(self.address)>>(32-self.prefix)
    }
    pub fn prefix(self)->u8 {self.prefix}
    pub fn address(self)->Ipv4Addr {self.address}
    pub fn overlaps(self, other:Self)->bool {
        self.contains(other.address) || other.contains(self.address)
    }
}
impl FromStr for Network {
    type Err=anyhow::Error;
    fn from_str(value:&str)->Result<Self> {
        ensure!(value.len()<=18,"LAN prefix exceeds size limit");
        let (address,prefix)=value.split_once('/').ok_or_else(||anyhow::anyhow!("LAN prefix requires CIDR notation"))?;
        let address=address.parse()?;let network=Self::from_address(address,prefix.parse()?)?;
        ensure!(network.address==address,"LAN prefix must use its network address");
        Ok(network)
    }
}
impl TryFrom<String> for Network {
    type Error=anyhow::Error;
    fn try_from(value:String)->Result<Self> {value.parse()}
}
impl From<Network> for String {fn from(value:Network)->Self {value.to_string()}}
impl fmt::Display for Network {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {write!(f,"{}/{}",self.address,self.prefix)}
}

/// Input order is UI priority. Prefer a more specific network, then the first
/// matching peer. Call with authorized, currently available peers only.
pub fn choose<'a>(target:Ipv4Addr,peers:impl IntoIterator<Item=(&'a str,&'a [Network])>)->Option<&'a str> {
    select(target,peers,false)
}

/// A sole available peer may reach further private networks through its own
/// router. With multiple available peers, an unmatched destination is ambiguous.
pub fn choose_with_single_fallback<'a>(target:Ipv4Addr,peers:impl IntoIterator<Item=(&'a str,&'a [Network])>)->Option<&'a str> {
    select(target,peers,true)
}
fn select<'a>(target:Ipv4Addr,peers:impl IntoIterator<Item=(&'a str,&'a [Network])>,fallback:bool)->Option<&'a str> {
    let mut chosen=None;let mut longest=0;let mut single=None;let mut count=0;
    for (peer,networks) in peers {
        count+=1;single=Some(peer);
        if let Some(prefix)=networks.iter().filter(|network|network.contains(target)).map(|network|network.prefix()).max() {
            if chosen.is_none() || prefix>longest {chosen=Some(peer);longest=prefix;}
        }
    }
    chosen.or_else(||if fallback && count==1 && target.is_private(){single}else{None})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn advertisements_are_canonical_and_private() {
        for raw in ["0.0.0.0/0","8.8.8.0/24","127.0.0.0/8","169.254.0.0/16","100.64.0.0/10","10.0.0.0/7","192.168.0.1/24","10.0.0.0/33"] {assert!(raw.parse::<Network>().is_err(),"{raw}");}
        assert_eq!(Network::from_address("192.168.86.130".parse().unwrap(),24).unwrap().to_string(),"192.168.86.0/24");
    }
    #[test]
    fn distinct_networks_specific_routes_and_priority_are_deterministic() {
        let broad=vec!["192.168.0.0/16".parse().unwrap()];
        let deep=vec!["192.168.86.0/24".parse().unwrap()];
        let condor=vec!["192.168.80.0/24".parse().unwrap()];
        let peers=||[ ("broad",broad.as_slice()),("deep",deep.as_slice()),("condor",condor.as_slice()) ];
        assert_eq!(choose("192.168.86.20".parse().unwrap(),peers()),Some("deep"));
        assert_eq!(choose("192.168.80.20".parse().unwrap(),peers()),Some("condor"));
        assert_eq!(choose("192.168.7.20".parse().unwrap(),peers()),Some("broad"));
        assert_eq!(choose("10.0.0.1".parse().unwrap(),peers()),None);
        assert_eq!(choose("192.168.86.20".parse().unwrap(),[("preferred",deep.as_slice()),("other",deep.as_slice())]),Some("preferred"));
    }
    #[test]
    fn one_available_exit_can_reach_private_destinations_behind_its_router() {
        let networks=vec!["10.20.0.0/16".parse().unwrap()];
        let target="192.168.0.153".parse().unwrap();
        assert_eq!(choose_with_single_fallback(target,[("deep",networks.as_slice())]),Some("deep"));
        assert_eq!(choose_with_single_fallback(target,[("deep",networks.as_slice()),("condor",networks.as_slice())]),None);
        assert_eq!(choose_with_single_fallback("1.1.1.1".parse().unwrap(),[("deep",networks.as_slice())]),None);
        assert_eq!(choose_with_single_fallback(target,std::iter::empty()),None);
    }

}
