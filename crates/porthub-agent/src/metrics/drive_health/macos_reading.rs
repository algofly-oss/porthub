//! Optional diskutil SMART details. Keys are not a guaranteed OS ABI: recognize
//! only known typed fields, and retain the native assessment when details vanish.
use super::Reading;
use serde_json::Value;
const DETAILS: &str = "SMARTDeviceSpecificKeysMayVaryNotGuaranteed";
fn integer(data: &Value, key: &str) -> Option<u64> { data.get(key)?.as_u64() }
fn wide(data: &Value, key: &str) -> Option<u128> {
    let low = integer(data, &format!("{key}_0"))?;
    let high = integer(data, &format!("{key}_1"))?;
    Some((u128::from(high) << 64) | u128::from(low))
}
fn counter(data: &Value, key: &str) -> Option<u64> {
    let value = wide(data, key)?;
    (value <= i64::MAX as u128).then_some(value as u64)
}
fn percent(data: &Value, key: &str) -> Option<u8> {
    integer(data, key).filter(|v| *v <= 100).map(|v| v as u8)
}
pub(super) fn has_nvme_details(data: &Value) -> bool {
    let details = &data[DETAILS];
    details.is_object() && ["DATA_UNITS_READ_0", "DATA_UNITS_WRITTEN_0", "AVAILABLE_SPARE", "PERCENTAGE_USED"].iter().any(|key| details.get(*key).is_some())
}
pub(super) fn parse(data: &Value) -> Result<Reading, String> {
    let mut out = Reading {self_test:"unsupported".into(), ..Default::default()};
    match data["SMARTStatus"].as_str() {
        Some("Verified") => {},
        Some("Failing" | "Failure") => {out.critical=true;out.reasons.push("The native storage driver reports SMART failure".into());},
        _ => return Err("The native storage driver does not provide SMART health".into()),
    }
    if !has_nvme_details(data) { return Ok(out); }
    let details=&data[DETAILS];
    out.temperature=integer(details,"TEMPERATURE").filter(|v|*v>0&&*v<=u16::MAX as u64).map(|v|v as f32-273.15).filter(|v|(-40.0..=150.0).contains(v));
    out.percentage_used=integer(details,"PERCENTAGE_USED").and_then(|v|u8::try_from(v).ok());
    out.available_spare=percent(details,"AVAILABLE_SPARE");
    out.spare_threshold=percent(details,"AVAILABLE_SPARE_THRESHOLD");
    out.power_on_hours=counter(details,"POWER_ON_HOURS");
    out.power_cycles=counter(details,"POWER_CYCLES");
    out.unsafe_shutdowns=counter(details,"UNSAFE_SHUTDOWNS");
    out.media_errors=counter(details,"MEDIA_ERRORS");
    out.lifetime_read_bytes=wide(details,"DATA_UNITS_READ").and_then(|v|super::nvme_bytes(&v.to_le_bytes()));
    out.lifetime_written_bytes=wide(details,"DATA_UNITS_WRITTEN").and_then(|v|super::nvme_bytes(&v.to_le_bytes()));
    if let Some(warning)=integer(details,"CRITICAL_WARNING").and_then(|v|u8::try_from(v).ok()) {
        if warning & 0xfd != 0 {out.critical=true;out.reasons.push(format!("NVMe critical warning flags: 0x{warning:02x}"));}
        if warning & 2 != 0 {out.reasons.push("Drive temperature is elevated".into());}
    }
    if out.temperature.is_some_and(|v|v>=70.) && !out.reasons.iter().any(|r|r=="Drive temperature is elevated") {out.reasons.push("Drive temperature is elevated".into());}
    if out.percentage_used.is_some_and(|v|v>=100) {out.critical=true;out.reasons.push("Rated SSD endurance has been used".into());}
    else if out.percentage_used.is_some_and(|v|v>=90) {out.reasons.push("SSD is nearing its rated endurance".into());}
    if out.available_spare.zip(out.spare_threshold).is_some_and(|(spare,threshold)|spare<threshold){out.critical=true;out.reasons.push("Available spare is below the drive threshold".into());}
    if out.media_errors.is_some_and(|v|v>0){out.reasons.push("Media or data-integrity errors recorded".into());}
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn actual() -> Value { json!({"SMARTStatus":"Verified",DETAILS:{"TEMPERATURE":304,"AVAILABLE_SPARE":100,"AVAILABLE_SPARE_THRESHOLD":99,"PERCENTAGE_USED":1,"POWER_ON_HOURS_0":1162,"POWER_ON_HOURS_1":0,"POWER_CYCLES_0":261,"POWER_CYCLES_1":0,"UNSAFE_SHUTDOWNS_0":16,"UNSAFE_SHUTDOWNS_1":0,"MEDIA_ERRORS_0":0,"MEDIA_ERRORS_1":0,"DATA_UNITS_READ_0":128039542,"DATA_UNITS_READ_1":0,"DATA_UNITS_WRITTEN_0":53486789,"DATA_UNITS_WRITTEN_1":0}}) }
    #[test]
    fn actual_apple_nvme_details_preserve_supported_zero_and_lifetime_units(){
        let out=parse(&actual()).unwrap();
        assert!((out.temperature.unwrap()-30.85).abs()<0.01);assert_eq!(out.power_on_hours,Some(1162));assert_eq!(out.power_cycles,Some(261));assert_eq!(out.unsafe_shutdowns,Some(16));assert_eq!(out.media_errors,Some(0));assert_eq!(out.available_spare,Some(100));assert_eq!(out.spare_threshold,Some(99));assert_eq!(out.percentage_used,Some(1));assert_eq!(out.lifetime_read_bytes,Some(65556245504000));assert_eq!(out.lifetime_written_bytes,Some(27385235968000));assert!(!out.critical);assert!(out.reasons.is_empty());assert!(!out.short_test_supported);
    }
    #[test]
    fn optional_absent_changed_or_invalid_keys_do_not_fabricate_zero_health(){
        let old=json!({"SMARTStatus":"Verified"});let out=parse(&old).unwrap();assert!(!has_nvme_details(&old));assert_eq!(out.power_on_hours,None);assert_eq!(out.temperature,None);assert!(!out.critical);
        let mut data=actual();data[DETAILS]["TEMPERATURE"]=json!(-1);data[DETAILS]["AVAILABLE_SPARE_THRESHOLD"]=json!(255);data[DETAILS]["PERCENTAGE_USED"]=json!("1");data[DETAILS]["POWER_ON_HOURS_1"]=Value::Null;data[DETAILS]["DATA_UNITS_READ_1"]=json!(u64::MAX);
        let out=parse(&data).unwrap();assert_eq!(out.temperature,None);assert_eq!(out.spare_threshold,None);assert_eq!(out.percentage_used,None);assert_eq!(out.power_on_hours,None);assert_eq!(out.lifetime_read_bytes,None);assert!(!out.critical);
        assert!(parse(&json!({"SMARTStatus":"Unknown",DETAILS:{"PERCENTAGE_USED":0}})).is_err());
    }
    #[test]
    fn native_failure_and_validated_threshold_warnings_survive_partial_details(){
        let mut data=actual();data["SMARTStatus"]=json!("Failing");assert!(parse(&data).unwrap().critical);
        data["SMARTStatus"]=json!("Verified");data[DETAILS]["AVAILABLE_SPARE"]=json!(98);assert!(parse(&data).unwrap().critical);
        data[DETAILS]["AVAILABLE_SPARE"]=json!(100);data[DETAILS]["MEDIA_ERRORS_0"]=json!(2);let out=parse(&data).unwrap();assert!(!out.critical);assert!(!out.reasons.is_empty());
        data[DETAILS]["DATA_UNITS_READ_0"]=json!(0);assert_eq!(parse(&data).unwrap().lifetime_read_bytes,None);
    }
}
