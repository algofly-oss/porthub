//! Bounded active-configuration policy for onward imported audio/HID only.
use anyhow::{Context, Result, ensure};
use std::collections::{HashMap, HashSet};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Configuration {
    pub value: u8,
    pub interfaces: u8,
}
pub(super) fn validate(bytes: &[u8]) -> Result<Configuration> {
    ensure!(
        (9..=65535).contains(&bytes.len()) && bytes[0] == 9 && bytes[1] == 2,
        "Invalid imported USB configuration descriptor"
    );
    ensure!(
        u16::from_le_bytes([bytes[2], bytes[3]]) as usize == bytes.len(),
        "Imported USB configuration is truncated or has trailing data"
    );
    let count = bytes[4];
    let value = bytes[5];
    ensure!(
        (1..=32).contains(&count) && value > 0,
        "Imported USB interface count/configuration exceeds bound"
    );
    let (mut offset, mut descriptors) = (0, 0);
    let mut alternates = HashMap::new();
    let mut associations = HashMap::new();
    let mut endpoints: Option<(u8, HashSet<u8>)> = None;
    while offset < bytes.len() {
        ensure!(
            offset + 2 <= bytes.len(),
            "Truncated imported USB descriptor header"
        );
        let length = bytes[offset] as usize;
        let kind = bytes[offset + 1];
        ensure!(
            length >= 2 && offset + length <= bytes.len() && descriptors < 512,
            "Malformed or excessive imported USB descriptors"
        );
        let descriptor = &bytes[offset..offset + length];
        match kind {
            1 => anyhow::bail!("Device descriptor inside imported configuration"),
            2 => ensure!(
                offset == 0 && length == 9,
                "Duplicate imported USB configuration"
            ),
            4 => {
                if let Some((declared, seen)) = &endpoints {
                    ensure!(
                        *declared as usize == seen.len(),
                        "Imported endpoint count does not match its interface"
                    );
                }
                ensure!(
                    length == 9 && descriptor[2] < count && descriptor[4] <= 30,
                    "Invalid imported interface descriptor"
                );
                ensure!(
                    matches!(descriptor[5], 1 | 3),
                    "Onward forwarding supports imported audio/HID interfaces only; storage, serial and unknown functions are unsupported"
                );
                ensure!(
                    alternates.len() < 128
                        && alternates
                            .insert((descriptor[2], descriptor[3]), descriptor[5])
                            .is_none(),
                    "Duplicate or excessive imported interface alternate settings"
                );
                endpoints = Some((descriptor[4], HashSet::new()));
            }
            5 => {
                ensure!(
                    length >= 7 && descriptor[2] & 0x0f != 0 && descriptor[2] & 0x70 == 0,
                    "Invalid imported endpoint descriptor"
                );
                let (declared, seen) = endpoints
                    .as_mut()
                    .context("Imported endpoint precedes interface")?;
                ensure!(
                    seen.insert(descriptor[2]) && seen.len() <= *declared as usize,
                    "Duplicate or excessive imported endpoint descriptors"
                );
            }
            11 => {
                ensure!(
                    length == 8
                        && descriptor[3] > 0
                        && (descriptor[2] as u16 + descriptor[3] as u16) <= count as u16
                        && matches!(descriptor[4], 1 | 3),
                    "Invalid or unsupported imported interface association"
                );
                for interface in descriptor[2]..descriptor[2] + descriptor[3] {
                    ensure!(
                        associations.insert(interface, descriptor[4]).is_none(),
                        "Overlapping imported interface associations"
                    );
                }
            }
            _ => {} // Bounded class-specific descriptors retain their exact bytes.
        }
        offset += length;
        descriptors += 1;
    }
    if let Some((declared, seen)) = &endpoints {
        ensure!(
            *declared as usize == seen.len(),
            "Imported endpoint count does not match its interface"
        );
    }
    ensure!(
        alternates.iter().all(|((interface, _), class)| associations
            .get(interface)
            .is_none_or(|function| function == class)),
        "Imported interface disagrees with its association class"
    );
    ensure!(
        (0..count).all(|interface| alternates.contains_key(&(interface, 0))),
        "Imported USB configuration lacks declared interface alternate0"
    );
    Ok(Configuration {
        value,
        interfaces: count,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    const SENN: &[u8] = include_bytes!("fixtures/senn1377-1100-descriptors.bin");
    #[test]
    fn actual_senn_composite_three_audio_interfaces_are_supported() {
        assert_eq!(SENN.len(), 476);
        assert!(validate(SENN).is_err());
        assert_eq!(
            validate(&SENN[18..]).unwrap(),
            Configuration {
                value: 1,
                interfaces: 3
            }
        );
    }
    #[test]
    fn mixed_storage_vendor_or_unknown_interfaces_are_never_supported() {
        for class in [0, 2, 8, 0xff] {
            let mut b = SENN[18..].to_vec();
            let at = b.windows(2).position(|d| d == [9, 4]).unwrap();
            b[at + 5] = class;
            assert!(validate(&b).is_err());
        }
    }
    #[test]
    fn truncated_duplicate_or_missing_interface_metadata_is_rejected() {
        let b = &SENN[18..];
        assert!(validate(&b[..b.len() - 1]).is_err());
        let mut b = b.to_vec();
        b[4] = 4;
        assert!(validate(&b).is_err());
        let mut b = SENN[18..].to_vec();
        b[9] = 0;
        assert!(validate(&b).is_err());
    }
    #[test]
    fn malformed_endpoint_counts_or_mixed_iad_class_are_rejected() {
        let missing = [9, 4, 0, 0, 1, 1, 1, 0, 0];
        assert!(validate(&configuration(&missing, 1)).is_err());
        let mut duplicate = vec![9, 4, 0, 0, 2, 1, 1, 0, 0];
        duplicate.extend([7, 5, 0x81, 1, 96, 0, 1]);
        duplicate.extend([7, 5, 0x81, 1, 96, 0, 1]);
        assert!(validate(&configuration(&duplicate, 1)).is_err());
        let mut before = vec![7, 5, 0x81, 1, 96, 0, 1];
        before.extend([9, 4, 0, 0, 0, 1, 1, 0, 0]);
        assert!(validate(&configuration(&before, 1)).is_err());
        let mut iad = vec![8, 11, 0, 1, 1, 1, 0, 0];
        iad.extend([9, 4, 0, 0, 0, 3, 0, 0, 0]);
        assert!(validate(&configuration(&iad, 1)).is_err());
    }
    fn configuration(tail: &[u8], interfaces: u8) -> Vec<u8> {
        let mut bytes = vec![9, 2, 0, 0, interfaces, 1, 0, 0x80, 50];
        bytes.extend(tail);
        let n = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&n.to_le_bytes());
        bytes
    }
    #[test]
    fn all_alternates_and_iad_functions_are_checked() {
        let audio = [9, 4, 0, 0, 0, 1, 1, 0, 0];
        let mut mixed = audio.to_vec();
        mixed.extend([9, 4, 0, 1, 0, 8, 6, 80, 0]);
        assert!(validate(&configuration(&mixed, 1)).is_err());
        let mut iad = vec![8, 11, 0, 1, 1, 1, 0, 0];
        iad.extend(audio);
        assert!(validate(&configuration(&iad, 1)).is_ok());
        iad[4] = 8;
        assert!(validate(&configuration(&iad, 1)).is_err());
        iad[4] = 1;
        iad[3] = 2;
        assert!(validate(&configuration(&iad, 1)).is_err());
        let mut duplicate = audio.to_vec();
        duplicate.extend(audio);
        assert!(validate(&configuration(&duplicate, 1)).is_err());
    }
}
