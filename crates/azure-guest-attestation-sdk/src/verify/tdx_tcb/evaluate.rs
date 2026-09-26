// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pure policy for an already authenticated Intel TDX TCB Info v3 object.
//!
//! The caller authenticates collateral and enforces its validity interval. This
//! module performs no crypto, I/O, or migration-policy inference. Module-version,
//! initial-model, and order-sensitive status rules are evaluated independently.

use std::io;

use serde::Serialize;
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// The evaluated Intel TCB status, or an explicitly unevaluated result.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub enum TcbStatus {
    /// All evaluated TCB requirements are satisfied.
    UpToDate,
    /// Platform configuration changes are required.
    ConfigurationNeeded,
    /// Software hardening is required.
    SWHardeningNeeded,
    /// Both configuration changes and software hardening are required.
    ConfigurationAndSWHardeningNeeded,
    /// A TCB update is required.
    OutOfDate,
    /// A TCB update and configuration changes are required.
    OutOfDateConfigurationNeeded,
    /// The matched TCB is revoked.
    Revoked,
    /// The supplied evidence cannot establish a supported TCB status.
    NotEvaluated,
}

/// The policy assessment of one platform/module TCB combination.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct TcbAssessment {
    /// The resulting status; this is not a cryptographic-verification result.
    pub status: TcbStatus,
    /// The earlier matched platform/module TCB date, in RFC 3339 form.
    pub tcb_date: Option<String>,
    /// An explanation when evaluation could not establish a known status.
    pub reason: Option<String>,
}

/// Current, launch, and optional initial TCB assessments exposed to callers.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct TdxTcbResult {
    /// Assessment of the current TCB.
    pub current: TcbAssessment,
    /// Assessment of the launch TCB.
    pub launch: TcbAssessment,
    /// Assessment of the initial TCB, when evidence is available.
    pub initial: Option<TcbAssessment>,
    /// Status selected by the order-sensitive aggregation policy, not a total severity
    /// ordering. Inspect every component: a terminal current status can retain
    /// precedence over an initial status, and NotEvaluated dominates.
    pub aggregate_status: TcbStatus,
    /// TCB date associated with the aggregate assessment.
    pub aggregate_date: Option<String>,
}

struct PlatformLevel {
    cpu: [u8; 16],
    tee: [u8; 16],
    pce: u16,
    assessment: TcbAssessment,
}

struct ModuleLevel {
    svn: u8,
    assessment: TcbAssessment,
}

struct ModuleIdentity {
    version: u8,
    binding: ModuleBinding,
    levels: Vec<ModuleLevel>,
}

struct ModuleBinding {
    signer: [u8; 48],
    attributes: u64,
    mask: u64,
}

impl ModuleBinding {
    fn parse(value: &Value) -> io::Result<Self> {
        Ok(Self {
            signer: hex_field(value, "mrsigner")?,
            // Intel JSON encodes integers in display order; quote attributes
            // are a little-endian UINT64. Do not compare their raw byte order.
            attributes: u64::from_be_bytes(hex_field(value, "attributes")?),
            mask: u64::from_be_bytes(hex_field(value, "attributesMask")?),
        })
    }

    fn matches(&self, signer: &[u8; 48], attributes: &[u8; 8]) -> bool {
        signer == &self.signer && (u64::from_le_bytes(*attributes) & self.mask) == self.attributes
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn text<'a>(value: &'a Value, field: &str) -> io::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field} must be a string")))
}

fn array<'a>(value: &'a Value, field: &str) -> io::Result<&'a [Value]> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("{field} must be an array")))
}

fn number(value: &Value, field: &str, maximum: u64) -> io::Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .filter(|number| *number <= maximum)
        .ok_or_else(|| invalid(format!("{field} must be an integer in 0..={maximum}")))
}

fn hex_field<const N: usize>(value: &Value, field: &str) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    hex::decode_to_slice(text(value, field)?, &mut bytes)
        .map_err(|_| invalid(format!("{field} must contain exactly {} hex digits", N * 2)))?;
    Ok(bytes)
}

fn date(value: &str) -> io::Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| invalid(format!("invalid RFC 3339 date {value:?}: {error}")))
}

fn components(tcb: &Value, field: &str) -> io::Result<[u8; 16]> {
    let values = array(tcb, field)?;
    if values.len() != 16 {
        return Err(invalid(format!("{field} must have exactly 16 components")));
    }
    let mut result = [0; 16];
    for (output, component) in result.iter_mut().zip(values) {
        *output = number(component, "svn", u8::MAX.into())? as u8;
    }
    Ok(result)
}

fn assessment(value: &Value, issue_date: OffsetDateTime) -> io::Result<TcbAssessment> {
    let tcb_date = text(value, "tcbDate")?;
    if date(tcb_date)? > issue_date {
        return Err(invalid("tcbDate must not be later than issueDate"));
    }
    let raw_status = text(value, "tcbStatus")?;
    let status = match raw_status {
        "UpToDate" => TcbStatus::UpToDate,
        "ConfigurationNeeded" => TcbStatus::ConfigurationNeeded,
        "SWHardeningNeeded" => TcbStatus::SWHardeningNeeded,
        "ConfigurationAndSWHardeningNeeded" => TcbStatus::ConfigurationAndSWHardeningNeeded,
        "OutOfDate" => TcbStatus::OutOfDate,
        "OutOfDateConfigurationNeeded" => TcbStatus::OutOfDateConfigurationNeeded,
        "Revoked" => TcbStatus::Revoked,
        _ => TcbStatus::NotEvaluated,
    };
    let reason = (status == TcbStatus::NotEvaluated)
        .then(|| format!("unsupported TCB status {raw_status:?}"));
    Ok(TcbAssessment {
        status,
        tcb_date: Some(tcb_date.to_owned()),
        reason,
    })
}

fn unevaluated(reason: impl Into<String>) -> TcbAssessment {
    TcbAssessment {
        status: TcbStatus::NotEvaluated,
        tcb_date: None,
        reason: Some(reason.into()),
    }
}

fn platform_levels(info: &Value, issued: OffsetDateTime) -> io::Result<Vec<PlatformLevel>> {
    let values = array(info, "tcbLevels")?;
    if values.is_empty() {
        return Err(invalid("platform tcbLevels must not be empty"));
    }
    values
        .iter()
        .map(|value| {
            let tcb = &value["tcb"];
            Ok(PlatformLevel {
                cpu: components(tcb, "sgxtcbcomponents")?,
                tee: components(tcb, "tdxtcbcomponents")?,
                pce: number(tcb, "pcesvn", u16::MAX.into())? as u16,
                assessment: assessment(value, issued)?,
            })
        })
        .collect()
}

fn identities(info: &Value, issued: OffsetDateTime) -> io::Result<Vec<ModuleIdentity>> {
    // Older TDX v3 collateral need not contain this optional array. A module
    // version greater than zero still requires a matching identity at selection.
    if info.get("tdxModuleIdentities").is_none() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut seen = [false; 256];
    for value in array(info, "tdxModuleIdentities")? {
        let id = text(value, "id")?;
        let bytes = id.as_bytes();
        if bytes.len() != 6
            || !bytes[..4].eq_ignore_ascii_case(b"TDX_")
            || !bytes[4..].iter().all(u8::is_ascii_hexdigit)
        {
            return Err(invalid("module identity id must have the form TDX_XX"));
        }
        let version = u8::from_str_radix(&id[4..], 16)
            .map_err(|_| invalid("invalid module identity version"))?;
        if std::mem::replace(&mut seen[usize::from(version)], true) {
            return Err(invalid(format!("duplicate module identity {id}")));
        }
        let binding = ModuleBinding::parse(value)?;
        let values = array(value, "tcbLevels")?;
        if values.is_empty() {
            return Err(invalid("module tcbLevels must not be empty"));
        }
        let levels = values
            .iter()
            .map(|level| {
                Ok(ModuleLevel {
                    svn: number(&level["tcb"], "isvsvn", u8::MAX.into())? as u8,
                    assessment: assessment(level, issued)?,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        result.push(ModuleIdentity {
            version,
            binding,
            levels,
        });
    }
    Ok(result)
}

fn at_least(actual: &[u8], required: &[u8]) -> bool {
    actual.iter().zip(required).all(|(a, b)| a >= b)
}

fn earlier_date(left: Option<&str>, right: Option<&str>) -> io::Result<Option<String>> {
    match (left, right) {
        (Some(left), Some(right)) => Ok(Some(
            if date(left)? <= date(right)? {
                left
            } else {
                right
            }
            .to_owned(),
        )),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value.to_owned())),
        (None, None) => Ok(None),
    }
}

fn merge_module(platform: TcbAssessment, module: TcbAssessment) -> io::Result<TcbAssessment> {
    use TcbStatus::*;

    let pair = [&platform.status, &module.status];
    // A known revocation is not lost to a missing identity or an unknown status.
    let status = if pair.contains(&&Revoked) {
        Revoked
    } else if pair.contains(&&NotEvaluated) {
        NotEvaluated
    } else {
        let configuration = pair.iter().any(|status| {
            matches!(
                status,
                ConfigurationNeeded
                    | ConfigurationAndSWHardeningNeeded
                    | OutOfDateConfigurationNeeded
            )
        });
        let outdated = pair
            .iter()
            .any(|status| matches!(status, OutOfDate | OutOfDateConfigurationNeeded));
        let hardening = pair.iter().any(|status| {
            matches!(
                status,
                SWHardeningNeeded | ConfigurationAndSWHardeningNeeded
            )
        });
        match (outdated, configuration, hardening) {
            (true, true, _) => OutOfDateConfigurationNeeded,
            (true, false, _) => OutOfDate,
            (false, true, true) => ConfigurationAndSWHardeningNeeded,
            (false, true, false) => ConfigurationNeeded,
            (false, false, true) => SWHardeningNeeded,
            (false, false, false) => UpToDate,
        }
    };
    Ok(TcbAssessment {
        tcb_date: earlier_date(platform.tcb_date.as_deref(), module.tcb_date.as_deref())?,
        reason: if status == NotEvaluated {
            platform.reason.or(module.reason)
        } else {
            None
        },
        status,
    })
}

/// Assess a TCB using authenticated Intel TDX TCB Info v3 collateral.
///
/// Every level and identity is validated before selecting the first matching
/// level in supplied order. `pce = None` omits only the PCE comparison because
/// the initial platform evidence does not record it. `current_module = None`
/// omits only the signer/attribute binding, not module identity/SVN evaluation.
/// Malformed collateral returns `InvalidData`; unsupported or unmatched evidence
/// returns `NotEvaluated`, without hiding a known revocation.
pub(crate) fn assess(
    info: &Value,
    cpu: &[u8; 16],
    pce: Option<u16>,
    tee: &[u8; 16],
    current_module: Option<(&[u8; 48], &[u8; 8])>,
) -> io::Result<TcbAssessment> {
    if text(info, "id")? != "TDX" || number(info, "version", u64::MAX)? != 3 {
        return Err(invalid("expected Intel TDX TCB Info version 3"));
    }
    let issued = date(text(info, "issueDate")?)?;
    let levels = platform_levels(info, issued)?;
    let base_binding = ModuleBinding::parse(&info["tdxModule"])?;
    let identities = identities(info, issued)?;
    let version = tee[1];
    let first_component = if version == 0 { 0 } else { 2 };
    let platform = levels
        .iter()
        .find(|level| {
            at_least(cpu, &level.cpu)
                && pce.is_none_or(|pce| pce >= level.pce)
                && at_least(&tee[first_component..], &level.tee[first_component..])
        })
        .map(|level| level.assessment.clone())
        .unwrap_or_else(|| unevaluated("no matching platform TCB level"));

    let identity = identities
        .iter()
        .find(|identity| identity.version == version);
    let mut module = match identity {
        Some(identity) => identity
            .levels
            .iter()
            .find(|level| tee[0] >= level.svn)
            .map(|level| level.assessment.clone())
            .unwrap_or_else(|| unevaluated(format!("no matching TDX_{version:02X} ISV SVN level"))),
        None if version == 0 => TcbAssessment {
            status: TcbStatus::UpToDate,
            tcb_date: None,
            reason: None,
        },
        None => unevaluated(format!("required TDX_{version:02X} identity is missing")),
    };
    // Version zero always uses the singular tdxModule binding, even when an
    // optional TDX_00 identity supplies additional SVN/status evaluation.
    let binding = if version == 0 {
        Some(&base_binding)
    } else {
        identity.map(|identity| &identity.binding)
    };
    if let (Some((signer, attributes)), Some(binding)) = (current_module, binding) {
        if !binding.matches(signer, attributes) && module.status != TcbStatus::Revoked {
            module = unevaluated(format!(
                "TDX_{version:02X} signer/attribute binding mismatch"
            ));
        }
    }
    merge_module(platform, module)
}

/// Relax only outdated statuses whose TCB date meets an optional Unix-seconds baseline.
///
/// Missing dates cannot satisfy a baseline. Malformed supplied dates return
/// `InvalidData` before any change; revoked and unknown statuses are never relaxed.
pub(crate) fn apply_baseline(
    assessment: &mut TcbAssessment,
    baseline: Option<i64>,
) -> io::Result<()> {
    let Some(baseline) = baseline else {
        return Ok(());
    };
    let Some(tcb_date) = assessment.tcb_date.as_deref() else {
        return Ok(());
    };
    if date(tcb_date)?.unix_timestamp() >= baseline {
        assessment.status = match assessment.status {
            TcbStatus::OutOfDate => TcbStatus::UpToDate,
            TcbStatus::OutOfDateConfigurationNeeded => TcbStatus::ConfigurationNeeded,
            _ => return Ok(()),
        };
    }
    Ok(())
}

/// Select an assessment using the order-sensitive final-status policy.
///
/// An unevaluated input dominates even revocation here (unlike platform/module
/// convergence). Otherwise a current terminal status wins, then an other terminal
/// status, then an other degraded status if current is up to date. The selected
/// assessment's date and reason are retained unchanged.
pub(crate) fn aggregate(current: &TcbAssessment, other: &TcbAssessment) -> TcbAssessment {
    use TcbStatus::*;
    let terminal =
        |status: &TcbStatus| matches!(status, OutOfDate | OutOfDateConfigurationNeeded | Revoked);
    if current.status == NotEvaluated {
        current.clone()
    } else if other.status == NotEvaluated {
        other.clone()
    } else if terminal(&current.status) {
        current.clone()
    } else if terminal(&other.status) || (current.status == UpToDate && other.status != UpToDate) {
        other.clone()
    } else {
        current.clone()
    }
}

/// Match only the supported Emerald Rapids initial-model/FMSPC allowlist.
///
/// Model words are little-endian; only the stepping nibble in word one is masked.
/// No other processor models or FMSPCs are inferred from this mapping.
pub(crate) fn initial_model_matches(model: &[u8; 12], fmspc: &[u8; 6]) -> bool {
    const WORDS: [u32; 3] = [0x0000_0000, 0x000c_06f0, 0x8000_0000];
    const MASKS: [u32; 3] = [0xffff_ffff, 0xffff_fff0, 0xffff_ffff];
    let model_matches = model
        .as_chunks::<4>()
        .0
        .iter()
        .zip(WORDS.into_iter().zip(MASKS))
        .all(|(bytes, (expected, mask))| {
            let actual = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            actual & mask == expected
        });
    model_matches
        && matches!(
            *fmspc,
            [0x90, 0xc0, 0x6f, 0, 0, 0] | [0xb0, 0xc0, 0x6f, 0, 0, 0]
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OLD: &str = "2024-01-01T00:00:00Z";
    const NEW: &str = "2025-01-01T00:00:00Z";
    const ISSUED: &str = "2026-01-01T00:00:00Z";

    fn binding() -> Value {
        json!({
            "mrsigner": "11".repeat(48),
            "attributes": "0000000000000000",
            "attributesMask": "FFFFFFFFFFFFFFFF"
        })
    }

    fn platform(cpu: u8, tee: u8, pce: u16, status: &str) -> Value {
        json!({
            "tcb": {
                "sgxtcbcomponents": vec![json!({"svn": cpu}); 16],
                "tdxtcbcomponents": vec![json!({"svn": tee}); 16],
                "pcesvn": pce
            },
            "tcbDate": NEW,
            "tcbStatus": status
        })
    }

    fn identity(id: &str, svn: u8, status: &str) -> Value {
        let mut value = binding();
        value["id"] = json!(id);
        value["tcbLevels"] = json!([{
            "tcb": {"isvsvn": svn}, "tcbDate": OLD, "tcbStatus": status
        }]);
        value
    }

    fn info() -> Value {
        json!({
            "id": "TDX", "version": 3, "issueDate": ISSUED,
            "tdxModule": binding(),
            "tcbLevels": [platform(1, 0, 2, "UpToDate")]
        })
    }

    fn evaluate(info: &Value, tee: &[u8; 16]) -> TcbAssessment {
        assess(info, &[1; 16], Some(2), tee, Some((&[0x11; 48], &[0; 8]))).unwrap()
    }

    fn result(status: TcbStatus) -> TcbAssessment {
        TcbAssessment {
            status,
            tcb_date: Some(NEW.into()),
            reason: None,
        }
    }

    #[test]
    fn zero_version_without_identity_uses_all_components_and_pce() {
        let value = info();
        assert_eq!(evaluate(&value, &[0; 16]), result(TcbStatus::UpToDate));
        assert_eq!(
            assess(&value, &[1; 16], Some(1), &[0; 16], None)
                .unwrap()
                .status,
            TcbStatus::NotEvaluated
        );
        assert_eq!(
            assess(&value, &[1; 16], None, &[0; 16], None)
                .unwrap()
                .status,
            TcbStatus::UpToDate
        );
        for index in 0..16 {
            let mut value = info();
            value["tcbLevels"][0]["tcb"]["tdxtcbcomponents"][index]["svn"] = json!(1);
            assert_eq!(evaluate(&value, &[0; 16]).status, TcbStatus::NotEvaluated);
        }
    }

    #[test]
    fn cpu_and_tdx_comparisons_are_componentwise_not_lexicographic() {
        let mut cpu = [1; 16];
        cpu[0] = 255;
        cpu[15] = 0;
        assert_eq!(
            assess(&info(), &cpu, Some(2), &[0; 16], None)
                .unwrap()
                .status,
            TcbStatus::NotEvaluated
        );
        let mut value = info();
        value["tdxModuleIdentities"] = json!([identity("TDX_01", 1, "UpToDate")]);
        value["tcbLevels"][0]["tcb"]["tdxtcbcomponents"][15]["svn"] = json!(1);
        let mut tee = [0; 16];
        tee[0] = 1;
        tee[1] = 1;
        tee[2] = 255;
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::NotEvaluated);
        tee[15] = 1;
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::UpToDate);
    }

    #[test]
    fn selection_preserves_supplied_platform_and_identity_level_order() {
        let mut value = info();
        value["tcbLevels"] = json!([
            platform(2, 0, 2, "Revoked"),
            platform(0, 0, 0, "ConfigurationNeeded"),
            platform(1, 0, 2, "UpToDate")
        ]);
        assert_eq!(
            evaluate(&value, &[0; 16]).status,
            TcbStatus::ConfigurationNeeded
        );
        let mut module = identity("TDX_01", 3, "Revoked");
        module["tcbLevels"].as_array_mut().unwrap().extend([
            json!({"tcb": {"isvsvn": 0}, "tcbDate": OLD, "tcbStatus": "SWHardeningNeeded"}),
            json!({"tcb": {"isvsvn": 2}, "tcbDate": NEW, "tcbStatus": "UpToDate"}),
        ]);
        value["tdxModuleIdentities"] = json!([module]);
        let mut tee = [0; 16];
        tee[0] = 2;
        tee[1] = 1;
        let actual = evaluate(&value, &tee);
        assert_eq!(actual.status, TcbStatus::ConfigurationAndSWHardeningNeeded);
        assert_eq!(actual.tcb_date.as_deref(), Some(OLD));
    }

    #[test]
    fn nonzero_module_requires_identity_and_svn_even_without_binding_or_pce() {
        let mut value = info();
        let mut tee = [0; 16];
        tee[0] = 2;
        tee[1] = 10;
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::NotEvaluated);
        value["tdxModuleIdentities"] = json!([identity("tdx_0a", 3, "UpToDate")]);
        assert_eq!(
            assess(&value, &[1; 16], None, &tee, None).unwrap().status,
            TcbStatus::NotEvaluated
        );
        tee[0] = 3;
        // For nonzero versions the platform's first two TDX SVNs are ignored.
        for index in 0..2 {
            value["tcbLevels"][0]["tcb"]["tdxtcbcomponents"][index]["svn"] = json!(255);
        }
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::UpToDate);
        value["tdxModuleIdentities"][0]["id"] = json!("TDX_0B");
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::NotEvaluated);
    }

    #[test]
    fn optional_zero_identity_is_evaluated_but_singular_binding_is_authoritative() {
        let mut value = info();
        let mut module = identity("TDX_00", 1, "OutOfDate");
        module["mrsigner"] = json!("22".repeat(48));
        value["tdxModuleIdentities"] = json!([module]);
        assert_eq!(evaluate(&value, &[0; 16]).status, TcbStatus::NotEvaluated);
        let mut tee = [0; 16];
        tee[0] = 1;
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::OutOfDate);
        value["tdxModule"]["mrsigner"] = json!("33".repeat(48));
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::NotEvaluated);
        assert_eq!(
            assess(&value, &[1; 16], None, &tee, None).unwrap().status,
            TcbStatus::OutOfDate
        );
    }

    #[test]
    fn binding_masks_use_numeric_hex_and_little_endian_quote_attributes() {
        for version in [0, 1] {
            let mut value = info();
            value["tdxModuleIdentities"] = json!([identity("TDX_01", 0, "UpToDate")]);
            let target = if version == 0 {
                &mut value["tdxModule"]
            } else {
                &mut value["tdxModuleIdentities"][0]
            };
            target["attributes"] = json!("8000000000000001");
            target["attributesMask"] = json!("8000000000000001");
            let mut tee = [0; 16];
            tee[1] = version;
            for (attributes, expected) in [
                (0x8000_0000_0000_0001u64, TcbStatus::UpToDate),
                (0x8000_0000_0000_0041u64, TcbStatus::UpToDate),
                (0x8000_0000_0000_0000u64, TcbStatus::NotEvaluated),
                (1u64, TcbStatus::NotEvaluated),
            ] {
                let attributes = attributes.to_le_bytes();
                assert_eq!(
                    assess(
                        &value,
                        &[1; 16],
                        Some(2),
                        &tee,
                        Some((&[0x11; 48], &attributes))
                    )
                    .unwrap()
                    .status,
                    expected
                );
            }
            let attributes = 0x8000_0000_0000_0001u64.to_le_bytes();
            assert_eq!(
                assess(
                    &value,
                    &[1; 16],
                    Some(2),
                    &tee,
                    Some((&[0x22; 48], &attributes))
                )
                .unwrap()
                .status,
                TcbStatus::NotEvaluated
            );
        }
    }

    #[test]
    fn unknown_statuses_are_not_evaluated_and_revocation_is_preserved() {
        let mut value = info();
        value["tcbLevels"][0]["tcbStatus"] = json!("FutureStatus");
        let actual = evaluate(&value, &[0; 16]);
        assert_eq!(actual.status, TcbStatus::NotEvaluated);
        assert!(actual.reason.unwrap().contains("FutureStatus"));
        value["tcbLevels"][0]["tcbStatus"] = json!("Revoked");
        let mut tee = [0; 16];
        tee[1] = 1;
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::Revoked);
        value["tdxModuleIdentities"] = json!([identity("TDX_01", 0, "FutureStatus")]);
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::Revoked);
        value["tcbLevels"][0]["tcbStatus"] = json!("UpToDate");
        let actual = evaluate(&value, &tee);
        assert_eq!(actual.status, TcbStatus::NotEvaluated);
        assert!(actual.reason.unwrap().contains("FutureStatus"));
        value["tdxModuleIdentities"][0]["tcbLevels"][0]["tcbStatus"] = json!("Revoked");
        value["tdxModuleIdentities"][0]["mrsigner"] = json!("22".repeat(48));
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::Revoked);
    }

    #[test]
    fn malformed_platform_fields_are_errors_even_after_a_matching_level() {
        for (pointer, replacement) in [
            ("/tcb/sgxtcbcomponents", json!([])),
            ("/tcb/tdxtcbcomponents", json!(vec![json!({"svn": 0}); 17])),
            ("/tcb/sgxtcbcomponents/0/svn", json!(256)),
            ("/tcb/sgxtcbcomponents/0/svn", json!(-1)),
            ("/tcb/tdxtcbcomponents/15/svn", json!(1.5)),
            ("/tcb/tdxtcbcomponents/15/svn", json!("1")),
            ("/tcb/pcesvn", json!(65536)),
            ("/tcb/pcesvn", Value::Null),
            ("/tcbDate", json!("2025-02-30T00:00:00Z")),
            ("/tcbDate", json!("2025-01-01")),
            ("/tcbDate", json!("2026-01-01T00:00:00.001Z")),
            ("/tcbStatus", Value::Null),
        ] {
            let mut malformed = platform(255, 255, 65535, "UpToDate");
            *malformed.pointer_mut(pointer).unwrap() = replacement;
            let mut value = info();
            value["tcbLevels"].as_array_mut().unwrap().push(malformed);
            let error = assess(&value, &[1; 16], None, &[0; 16], None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{pointer}");
        }
    }

    #[test]
    fn malformed_unselected_identities_are_errors() {
        for (pointer, replacement) in [
            ("/id", json!("TDX_1")),
            ("/id", json!("TDX_GG")),
            ("/id", json!("TDX_é")),
            ("/mrsigner", json!("aa")),
            ("/attributes", json!("GG00000000000000")),
            ("/attributesMask", json!(0)),
            ("/tcbLevels", json!([])),
            ("/tcbLevels/0/tcb/isvsvn", json!(256)),
            ("/tcbLevels/0/tcb/isvsvn", Value::Null),
            ("/tcbLevels/0/tcbDate", json!("2027-01-01T00:00:00Z")),
            ("/tcbLevels/0/tcbStatus", json!(7)),
        ] {
            let mut module = identity("TDX_02", 0, "UpToDate");
            *module.pointer_mut(pointer).unwrap() = replacement;
            let mut value = info();
            value["tdxModuleIdentities"] = json!([module]);
            assert!(
                assess(&value, &[1; 16], None, &[0; 16], None).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn malformed_headers_arrays_and_duplicate_identities_are_errors() {
        for (field, replacement) in [
            ("id", json!("SGX")),
            ("version", json!(2)),
            ("issueDate", json!("not-a-date")),
            ("tcbLevels", json!([])),
            ("tcbLevels", Value::Null),
            ("tdxModule", Value::Null),
            ("tdxModuleIdentities", Value::Null),
            ("tdxModuleIdentities", json!({})),
            (
                "tdxModuleIdentities",
                json!([
                    identity("TDX_0A", 0, "UpToDate"),
                    identity("tdx_0a", 0, "Revoked")
                ]),
            ),
        ] {
            let mut value = info();
            value[field] = replacement;
            assert!(
                assess(&value, &[1; 16], None, &[0; 16], None).is_err(),
                "{field}"
            );
        }
        for field in ["id", "version", "issueDate", "tcbLevels", "tdxModule"] {
            let mut value = info();
            value.as_object_mut().unwrap().remove(field);
            assert!(assess(&value, &[1; 16], None, &[0; 16], None).is_err());
        }
    }

    #[test]
    fn dates_compare_instants_not_text_and_include_both_matched_levels() {
        let mut value = info();
        value["tcbLevels"][0]["tcbDate"] = json!("2025-01-01T01:00:00+02:00");
        value["tdxModuleIdentities"] = json!([identity("TDX_01", 0, "UpToDate")]);
        value["tdxModuleIdentities"][0]["tcbLevels"][0]["tcbDate"] = json!(NEW);
        let mut tee = [0; 16];
        tee[1] = 1;
        assert_eq!(
            evaluate(&value, &tee).tcb_date.as_deref(),
            Some("2025-01-01T01:00:00+02:00")
        );
        value["tcbLevels"][0]["tcbDate"] = json!(NEW);
        value["tdxModuleIdentities"][0]["tcbLevels"][0]["tcbDate"] = json!(OLD);
        assert_eq!(evaluate(&value, &tee).tcb_date.as_deref(), Some(OLD));
        value["tcbLevels"][0]["tcbDate"] = json!("2026-01-01T01:00:00+01:00");
        assert_eq!(evaluate(&value, &tee).status, TcbStatus::UpToDate);
    }

    fn statuses() -> [TcbStatus; 8] {
        use TcbStatus::*;
        [
            UpToDate,
            ConfigurationNeeded,
            SWHardeningNeeded,
            ConfigurationAndSWHardeningNeeded,
            OutOfDate,
            OutOfDateConfigurationNeeded,
            Revoked,
            NotEvaluated,
        ]
    }

    #[test]
    fn module_convergence_covers_every_status_pair() {
        use TcbStatus::*;
        // Rows are platform statuses, columns are module statuses in statuses().
        let expected = [
            [0, 1, 2, 3, 4, 5, 6, 7],
            [1, 1, 3, 3, 5, 5, 6, 7],
            [2, 3, 2, 3, 4, 5, 6, 7],
            [3, 3, 3, 3, 5, 5, 6, 7],
            [4, 5, 4, 5, 4, 5, 6, 7],
            [5, 5, 5, 5, 5, 5, 6, 7],
            [6, 6, 6, 6, 6, 6, 6, 6],
            [7, 7, 7, 7, 7, 7, 6, 7],
        ];
        let statuses = statuses();
        for (i, platform) in statuses.iter().enumerate() {
            for (j, module) in statuses.iter().enumerate() {
                let mut value = info();
                value["tcbLevels"][0]["tcbStatus"] = serde_json::to_value(platform).unwrap();
                let module_name = serde_json::to_value(module).unwrap();
                value["tdxModuleIdentities"] =
                    json!([identity("TDX_01", 0, module_name.as_str().unwrap())]);
                let mut tee = [0; 16];
                tee[1] = 1;
                let actual = evaluate(&value, &tee);
                assert_eq!(
                    actual.status, statuses[expected[i][j]],
                    "{platform:?}, {module:?}"
                );
                assert_eq!(actual.tcb_date.as_deref(), Some(OLD));
                assert_eq!(actual.reason.is_some(), actual.status == NotEvaluated);
                if *platform != UpToDate || *module != UpToDate {
                    assert_ne!(actual.status, UpToDate);
                }
            }
        }
    }

    #[test]
    fn baseline_relaxes_only_the_two_outdated_statuses_at_or_after_cutoff() {
        let timestamp = date(NEW).unwrap().unix_timestamp();
        for status in statuses() {
            for baseline in [
                None,
                Some(timestamp - 1),
                Some(timestamp),
                Some(timestamp + 1),
            ] {
                let mut value = result(status.clone());
                apply_baseline(&mut value, baseline).unwrap();
                let expected = if baseline.is_some_and(|baseline| baseline <= timestamp) {
                    match status {
                        TcbStatus::OutOfDate => TcbStatus::UpToDate,
                        TcbStatus::OutOfDateConfigurationNeeded => TcbStatus::ConfigurationNeeded,
                        _ => status.clone(),
                    }
                } else {
                    status.clone()
                };
                assert_eq!(value.status, expected);
                assert_eq!(value.tcb_date.as_deref(), Some(NEW));
            }
        }
    }

    #[test]
    fn baseline_uses_earlier_module_date_and_does_not_invent_missing_dates() {
        let mut value = info();
        value["tcbLevels"][0]["tcbStatus"] = json!("OutOfDate");
        value["tdxModuleIdentities"] = json!([identity("TDX_01", 0, "UpToDate")]);
        let mut tee = [0; 16];
        tee[1] = 1;
        let mut actual = evaluate(&value, &tee);
        apply_baseline(&mut actual, Some(date(NEW).unwrap().unix_timestamp())).unwrap();
        assert_eq!(actual.status, TcbStatus::OutOfDate);
        actual.tcb_date = None;
        apply_baseline(&mut actual, Some(i64::MIN)).unwrap();
        assert_eq!(actual.status, TcbStatus::OutOfDate);
        actual.tcb_date = Some("not-a-date".into());
        let before = actual.clone();
        assert!(apply_baseline(&mut actual, Some(0)).is_err());
        assert_eq!(actual, before);
        apply_baseline(&mut actual, None).unwrap();
    }

    #[test]
    fn final_aggregation_covers_every_ordered_pair_and_retains_selected_metadata() {
        let selected_other = [
            [false, true, true, true, true, true, true, true],
            [false, false, false, false, true, true, true, true],
            [false, false, false, false, true, true, true, true],
            [false, false, false, false, true, true, true, true],
            [false, false, false, false, false, false, false, true],
            [false, false, false, false, false, false, false, true],
            [false, false, false, false, false, false, false, true],
            [false, false, false, false, false, false, false, false],
        ];
        for (i, current) in statuses().into_iter().enumerate() {
            for (j, other) in statuses().into_iter().enumerate() {
                let current = result(current.clone());
                let mut other = result(other);
                other.tcb_date = Some(OLD.into());
                other.reason = Some("other assessment".into());
                assert_eq!(
                    aggregate(&current, &other),
                    if selected_other[i][j] { other } else { current }
                );
            }
        }
    }

    #[test]
    fn initial_model_mapping_allows_only_documented_fmspcs_and_stepping_mask() {
        let mut model = [0; 12];
        model[4..8].copy_from_slice(&0x000c_06f0u32.to_le_bytes());
        model[8..12].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        let fmspc = [0x90, 0xc0, 0x6f, 0, 0, 0];
        for stepping in 0..16 {
            model[4] = 0xf0 | stepping;
            assert!(initial_model_matches(&model, &fmspc));
            assert!(initial_model_matches(&model, &[0xb0, 0xc0, 0x6f, 0, 0, 0]));
        }
        for bit in 0..96 {
            if (32..36).contains(&bit) {
                continue;
            }
            let mut changed = model;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert!(!initial_model_matches(&changed, &fmspc), "model bit {bit}");
        }
        for bit in 0..48 {
            let mut changed = fmspc;
            changed[bit / 8] ^= 1 << (bit % 8);
            // The second explicitly allowed FMSPC differs in precisely this bit.
            assert_eq!(initial_model_matches(&model, &changed), bit == 5);
        }
        assert!(!initial_model_matches(&[0; 12], &fmspc));
        assert!(!initial_model_matches(&model, &[0; 6]));
        model[4..8].copy_from_slice(&0x000c_06f0u32.to_be_bytes());
        assert!(!initial_model_matches(&model, &fmspc));
    }

    #[test]
    fn public_result_types_serialize_exact_status_names() {
        let current = result(TcbStatus::ConfigurationAndSWHardeningNeeded);
        let value = TdxTcbResult {
            current: current.clone(),
            launch: current.clone(),
            initial: None,
            aggregate_status: current.status.clone(),
            aggregate_date: current.tcb_date.clone(),
        };
        let json = serde_json::to_value(value.clone()).unwrap();
        assert_eq!(
            json["current"]["status"],
            "ConfigurationAndSWHardeningNeeded"
        );
        assert_eq!(json["aggregate_status"], json["current"]["status"]);
        assert_eq!(json["aggregate_date"], NEW);
        assert!(json["initial"].is_null());
        assert_eq!(value.current, value.launch);
    }
}
