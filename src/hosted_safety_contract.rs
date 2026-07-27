use serde_json::Value;

const FIXTURE: &str = include_str!("../contracts/hosted-lite-safety-v1.fixture.json");
const SCHEMA: &str = include_str!("../contracts/hosted-lite-safety-v1.schema.json");

pub(crate) fn validate_embedded_contract() -> Result<(), String> {
    let fixture: Value =
        serde_json::from_str(FIXTURE).map_err(|error| format!("contract fixture: {error}"))?;
    let _: Value =
        serde_json::from_str(SCHEMA).map_err(|error| format!("contract schema: {error}"))?;
    if fixture["contract"] != "clavenar.hosted-lite-safety/v1"
        || fixture.pointer("/authentication/anonymousMcp") != Some(&Value::Bool(false))
        || fixture.pointer("/authentication/agentOperatorOverlap")
            != Some(&Value::String("reject-constant-time".to_string()))
        || fixture.pointer("/posture/mode") != Some(&Value::String("enforce".to_string()))
        || fixture.pointer("/rateLimit/required") != Some(&Value::Bool(true))
        || fixture.pointer("/durability/scaleToZero") != Some(&Value::Bool(false))
        || fixture.pointer("/adapter/identifier")
            != Some(&Value::String("mcp-jsonrpc-v1".to_string()))
        || fixture.pointer("/adapter/responseId")
            != Some(&Value::String("exact-request-id".to_string()))
    {
        return Err("embedded hosted Lite safety contract is weakened".to_string());
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
