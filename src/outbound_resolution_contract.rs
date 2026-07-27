use serde_json::Value;

const FIXTURE: &str = include_str!("../contracts/outbound-resolution-pinning-v1.fixture.json");
const SCHEMA: &str = include_str!("../contracts/outbound-resolution-pinning-v1.schema.json");

pub(crate) fn validate_embedded_contract() -> Result<(), String> {
    let fixture: Value =
        serde_json::from_str(FIXTURE).map_err(|error| format!("contract fixture: {error}"))?;
    let _: Value =
        serde_json::from_str(SCHEMA).map_err(|error| format!("contract schema: {error}"))?;
    if fixture["contract"] != "clavenar.outbound-resolution-pinning/v1"
        || fixture.pointer("/resolution/rejectWholeSetOnAnyNonPublicAnswer")
            != Some(&Value::Bool(true))
        || fixture.pointer("/resolution/pinSelectedAddress") != Some(&Value::Bool(true))
        || fixture.pointer("/resolution/applicationClientReresolution") != Some(&Value::Bool(false))
        || fixture.pointer("/redirects/mode") != Some(&Value::String("manual".to_string()))
        || fixture.pointer("/redirects/maximumHops") != Some(&Value::from(5))
        || fixture.pointer("/redirects/validateAndRepinEveryHop") != Some(&Value::Bool(true))
    {
        return Err("embedded outbound resolution contract is weakened".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_contract_is_valid() {
        validate_embedded_contract().unwrap();
    }
}
