//! Bounded relay batches. Prefix encoding removes repeated peer/IP headers;
//! decoding restores the exact records before ordinary identity/ACL validation.
use anyhow::{ensure, Result};
use bytes::{Bytes, BytesMut};

pub const LEGACY: &[u8; 4] = b"PHB1";
pub const PREFIX: &[u8; 4] = b"PHB2";
const MAX_RECORDS: usize = 32;
const MAX_RECORD: usize = 1441;

pub fn encode(records: &[impl AsRef<[u8]>], prefixes: bool) -> Result<Vec<u8>> {
    ensure!(
        !records.is_empty() && records.len() <= MAX_RECORDS,
        "invalid relay batch count"
    );
    let mut output =
        Vec::with_capacity(4 + records.iter().map(|r| r.as_ref().len() + 3).sum::<usize>());
    output.extend_from_slice(if prefixes { PREFIX } else { LEGACY });
    let mut previous: &[u8] = &[];
    for record in records {
        let record = record.as_ref();
        ensure!(
            !record.is_empty() && record.len() <= MAX_RECORD,
            "invalid relay record size"
        );
        let common = if prefixes {
            previous
                .iter()
                .zip(record)
                .take(255)
                .take_while(|(a, b)| a == b)
                .count()
        } else {
            0
        };
        let suffix = &record[common..];
        output.extend_from_slice(&(suffix.len() as u16).to_be_bytes());
        if prefixes {
            output.push(common as u8);
        }
        output.extend_from_slice(suffix);
        previous = record;
    }
    Ok(output)
}

pub fn decode(frame: Bytes) -> Result<Vec<Bytes>> {
    let prefixes = frame.starts_with(PREFIX);
    if !prefixes && !frame.starts_with(LEGACY) {
        return Ok(vec![frame]);
    }
    let mut records: Vec<Bytes> = Vec::with_capacity(MAX_RECORDS);
    let mut offset = 4;
    while offset < frame.len() {
        let header = if prefixes { 3 } else { 2 };
        ensure!(
            records.len() < MAX_RECORDS && frame.len() - offset >= header,
            "invalid relay batch header"
        );
        let length = usize::from(u16::from_be_bytes([frame[offset], frame[offset + 1]]));
        let common = if prefixes {
            usize::from(frame[offset + 2])
        } else {
            0
        };
        offset += header;
        ensure!(
            length <= frame.len() - offset && common + length > 0 && common + length <= MAX_RECORD,
            "invalid relay record size"
        );
        ensure!(
            common <= records.last().map_or(0, Bytes::len),
            "invalid relay record prefix"
        );
        let record = if common == 0 {
            frame.slice(offset..offset + length)
        } else {
            let mut record = BytesMut::with_capacity(common + length);
            record.extend_from_slice(&records.last().unwrap()[..common]);
            record.extend_from_slice(&frame[offset..offset + length]);
            record.freeze()
        };
        records.push(record);
        offset += length;
    }
    ensure!(!records.is_empty(), "empty relay batch");
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_and_legacy_batches_restore_identical_records_with_bounded_expansion() -> Result<()> {
        let records: Vec<_> = (0..32)
            .map(|i| {
                let mut record = vec![7u8; 1400];
                record[70] = i;
                record[1399] = i;
                Bytes::from(record)
            })
            .collect();
        let legacy = encode(&records, false)?;
        let compact = encode(&records, true)?;
        assert!(compact.len() + 2000 < legacy.len());
        assert_eq!(decode(legacy.into())?, records);
        assert_eq!(decode(compact.into())?, records);
        let standalone = Bytes::from_static(b"standalone");
        assert_eq!(decode(standalone.clone())?, vec![standalone]);
        Ok(())
    }

    #[test]
    fn invalid_prefixes_sizes_counts_and_truncated_batches_are_rejected_atomically() {
        for data in [
            b"PHB2".as_slice(),
            b"PHB2\0\x01\x01x",
            b"PHB2\0\0\0",
            b"PHB2\0\x03\0x",
            b"PHB1\0\0",
        ] {
            assert!(decode(Bytes::copy_from_slice(data)).is_err());
        }
        let oversized = vec![vec![0u8; MAX_RECORD + 1]];
        assert!(encode(&oversized, true).is_err());
        let records = vec![vec![1u8]; MAX_RECORDS + 1];
        assert!(encode(&records, true).is_err());
        let mut invalid = encode(&records[..MAX_RECORDS], true).unwrap();
        invalid.extend_from_slice(&[0, 1, 0, 1]);
        assert!(decode(invalid.into()).is_err());
    }

    #[test]
    fn changing_headers_and_identical_records_round_trip() -> Result<()> {
        let records = [
            Bytes::from_static(b"a"),
            Bytes::from_static(b"a"),
            Bytes::from_static(b"b"),
            Bytes::from(vec![9; 1441]),
            Bytes::from(vec![9; 1441]),
        ];
        assert_eq!(decode(encode(&records, true)?.into())?, records);
        Ok(())
    }
}
