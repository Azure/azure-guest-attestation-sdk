// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! High-level attestation client for Azure Virtual Machines.
//!
//! [`AttestationClient`] is the main entry point. It owns the TPM connection
//! and HTTP client internally, so callers never need to manage those resources.
//!
//! Supports **Confidential VMs** (AMD SEV-SNP, Intel TDX) and
//! **TrustedLaunch** VMs. TrustedLaunch is auto-detected when the CVM report
//! NV index is absent.
//!
//! # Quick start
//!
//! ```no_run
//! use azure_guest_attestation_sdk::{AttestationClient, Provider};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = AttestationClient::new()?;
//!
//!     // One-shot attestation against MAA
//!     let result = client.attest_guest(
//!         Provider::maa("https://sharedeus.eus.attest.azure.net"),
//!         None,
//!     )?;
//!     println!("Token: {}", result.token.unwrap_or_default());
//!     Ok(())
//! }
//! ```

use crate::error::SdkError;
use crate::guest_attest::{
    self, GuestAttestationParameters, IsolationEvidence, IsolationInfo, IsolationType, MaaProvider,
    OsInfo, PcrEntry, TeeProof, TpmInfo,
};
use crate::report::{self, CvmAttestationReport, CvmReportType, RuntimeClaims};
use crate::tpm::attestation;
use crate::tpm::commands::TpmCommandExt;
use crate::tpm::device::Tpm;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Which attestation provider to use.
///
/// This is an enum rather than a trait object so the set of providers is
/// exhaustive and callers don't need to import extra traits.
#[derive(Debug, Clone)]
pub enum Provider {
    /// Microsoft Azure Attestation (MAA) service.
    Maa {
        /// MAA endpoint URL.
        ///
        /// Can be a bare base URL (e.g. `https://sharedeus.eus.attest.azure.net`)
        /// — the SDK will append the appropriate API path and version
        /// automatically.  Fully-qualified URLs (containing `/attest/`) are
        /// used as-is.
        endpoint: String,
    },
    /// Loopback provider for testing — echoes the request back as a JSON token.
    Loopback,
}

impl Provider {
    /// Shorthand constructor for [`Provider::Maa`].
    pub fn maa(endpoint: impl Into<String>) -> Self {
        Self::Maa {
            endpoint: endpoint.into(),
        }
    }
}

/// Type of device to collect evidence from.
///
/// Currently only TPM is supported; additional device types (e.g. vTPM,
/// GPU attestation) may be added in the future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceType {
    /// Trusted Platform Module (hardware or firmware TPM).
    Tpm,
}

/// Options for [`AttestationClient::get_device_evidence`].
///
/// The `Default` implementation selects [`DeviceType::Tpm`] with OS-default
/// PCR selection.
#[derive(Debug, Clone)]
pub struct DeviceEvidenceOptions {
    /// Which device to collect evidence from.
    pub device_type: DeviceType,
    /// PCR indices to include in the quote.
    ///
    /// When `None`, the OS-specific default set is used
    /// (see [`OsInfo::detect`](crate::guest_attest::OsInfo::detect)).
    pub pcr_selection: Option<Vec<u32>>,
}

impl Default for DeviceEvidenceOptions {
    fn default() -> Self {
        Self {
            device_type: DeviceType::Tpm,
            pcr_selection: None,
        }
    }
}

/// Which kind of endorsement to retrieve from the platform metadata service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndorsementKind {
    /// AMD SEV-SNP VCEK certificate chain (from Azure THIM / IMDS).
    Vcek,
}

/// Options for [`AttestationClient::get_cvm_evidence`].
///
/// All fields are optional; the `Default` implementation produces a
/// zero-configuration request that auto-detects the TEE type.
#[derive(Debug, Clone, Default)]
pub struct CvmEvidenceOptions {
    /// Optional user data (0–64 bytes) to embed in the TEE report.
    pub user_data: Option<Vec<u8>>,
    /// If `true`, fetch the platform-specific quote from IMDS
    /// (TD Quote on TDX; no-op on SNP/VBS).
    pub fetch_platform_quote: bool,
}

/// Options for [`AttestationClient::attest_guest`].
#[derive(Debug, Clone, Default)]
pub struct AttestOptions {
    /// Client-supplied key/value payload to include in the attestation request.
    /// Each value will be base64-encoded in the outgoing JSON.
    pub client_payload: Option<String>,
    /// PCR indices to include in the quote.
    ///
    /// When `None`, the OS-specific default set is used
    /// (see [`OsInfo::detect`](crate::guest_attest::OsInfo::detect)).
    pub pcr_selection: Option<Vec<u32>>,
}

/// TEE evidence collected from the CVM hardware.
#[derive(Debug, Clone)]
pub struct CvmEvidence {
    /// Auto-detected CVM report type.
    pub report_type: CvmReportType,
    /// Raw TEE report bytes, trimmed to the correct size for the detected type.
    pub tee_report: Vec<u8>,
    /// Runtime claims (if present in the NV-backed CVM report).
    pub runtime_claims: Option<RuntimeClaims>,
    /// Raw runtime claims bytes (empty if not present).
    pub runtime_data: Vec<u8>,
    /// Platform quote bytes (TD Quote for TDX, empty otherwise).
    /// Only populated when [`CvmEvidenceOptions::fetch_platform_quote`] is `true`.
    pub platform_quote: Vec<u8>,
}

/// Endorsement retrieved from the platform metadata service.
#[derive(Debug, Clone)]
pub struct Endorsement {
    /// The kind of endorsement this represents.
    pub kind: EndorsementKind,
    /// Raw endorsement data (e.g. PEM certificate chain for VCEK).
    pub data: Vec<u8>,
}

/// Result of a successful attestation.
#[derive(Debug, Clone)]
pub struct AttestResult {
    /// JWT token returned by the attestation provider (if the provider returns one).
    pub token: Option<String>,
    /// The raw JSON request body that was sent to the provider.
    pub request_json: String,
    /// Base64url-encoded request (as sent on the wire).
    pub encoded_request: String,
    /// PCR indices included in the quote.
    pub pcrs: Vec<u32>,
}

/// Full guest attestation report ready to submit to a provider.
///
/// This is the Rust-side representation of the JSON request body.
/// Use [`AttestationClient::create_attestation_report`] to build one,
/// or construct it manually from collected artifacts.
#[derive(Debug, Clone)]
pub struct AttestationReport {
    /// Serialized JSON request body.
    pub json: String,
    /// PCR indices included.
    pub pcrs: Vec<u32>,
}

/// TPM device evidence collected for attestation.
///
/// Bundles the serializable [`TpmInfo`] (for the guest attestation JSON request).
#[derive(Debug, Clone)]
pub struct DeviceEvidence {
    /// The TPM attestation artifacts (AK cert/pub, PCR quote, ephemeral key, etc.).
    pub tpm_info: TpmInfo,
    /// PCR indices used in the quote.
    pub pcrs: Vec<u32>,
}

// ---------------------------------------------------------------------------
// AttestationClient
// ---------------------------------------------------------------------------

/// Main entry point for CVM attestation.
///
/// Owns the TPM connection internally. Create one via [`AttestationClient::new`]
/// and call methods to collect evidence, endorsements, build reports, or perform
/// end-to-end attestation.
pub struct AttestationClient {
    tpm: Tpm,
}

impl AttestationClient {
    /// Open the platform TPM and create a new client.
    ///
    /// On Linux this tries `/dev/tpmrm0` then `/dev/tpm0`.
    /// On Windows this uses TBS (TPM Base Services).
    pub fn new() -> crate::error::Result<Self> {
        let tpm = Tpm::open()?;
        Ok(Self { tpm })
    }

    /// Create a client backed by a pre-opened [`Tpm`] handle.
    ///
    /// Useful for testing or when the caller has already opened the device.
    pub fn from_tpm(tpm: Tpm) -> Self {
        Self { tpm }
    }

    /// Reference to the underlying [`Tpm`] handle.
    pub fn tpm(&self) -> &Tpm {
        &self.tpm
    }

    // -----------------------------------------------------------------------
    // Evidence
    // -----------------------------------------------------------------------

    /// Collect TEE (CVM) evidence from the hardware.
    ///
    /// Auto-detects the TEE type (SNP, TDX, VBS) from the CVM report stored
    /// in the TPM NV index. Optionally embeds caller-supplied `user_data`
    /// (0–64 bytes) in the report.
    ///
    /// When `options.fetch_platform_quote` is `true` and the TEE is TDX,
    /// a TD Quote is fetched from IMDS and stored in [`CvmEvidence::platform_quote`].
    pub fn get_cvm_evidence(
        &self,
        options: Option<&CvmEvidenceOptions>,
    ) -> crate::error::Result<CvmEvidence> {
        let opts = options.cloned().unwrap_or_default();

        // Validate user data length
        if let Some(ref ud) = opts.user_data {
            if ud.len() > 64 {
                return Err(SdkError::Parse(format!(
                    "user_data length {} exceeds 64 bytes",
                    ud.len()
                )));
            }
        }

        let ud_slice = opts.user_data.as_deref();
        let raw = attestation::get_cvm_report_raw(&self.tpm, ud_slice)?;
        let (parsed, claims) = CvmAttestationReport::parse_with_runtime_claims(&raw)?;
        let rtype = parsed.runtime_claims_header.report_type;

        // Trim TEE report to expected size
        let expected_size = match rtype {
            CvmReportType::VbsVmReport => report::VBS_VM_REPORT_SIZE,
            CvmReportType::SnpVmReport => report::SNP_VM_REPORT_SIZE,
            CvmReportType::TdxVmReport => report::TDX_VM_REPORT_SIZE,
            CvmReportType::TvmReport | CvmReportType::Invalid => 0,
        };
        let tee_report = if expected_size > 0 {
            parsed.tee_report[..expected_size.min(parsed.tee_report.len())].to_vec()
        } else {
            Vec::new()
        };

        let runtime_data = parsed
            .get_runtime_claims_raw_bytes(&raw)
            .unwrap_or_default();

        // Optionally fetch platform quote (TDX only for now)
        let platform_quote = if opts.fetch_platform_quote && rtype == CvmReportType::TdxVmReport {
            let imds = guest_attest::ImdsClient::new();
            imds.get_td_quote(&tee_report)?
        } else {
            Vec::new()
        };

        Ok(CvmEvidence {
            report_type: rtype,
            tee_report,
            runtime_claims: claims,
            runtime_data,
            platform_quote,
        })
    }

    /// Collect device evidence: AK cert/pub, PCR quote + values, ephemeral key.
    ///
    /// The returned [`DeviceEvidence`] contains the serializable [`TpmInfo`]
    /// (for the guest attestation JSON request) and the ephemeral key handle
    /// needed later for token decryption.
    ///
    /// Pass `None` for `options` to use the default device (TPM) with
    /// OS-default PCR selection.
    pub fn get_device_evidence(
        &self,
        options: Option<&DeviceEvidenceOptions>,
    ) -> crate::error::Result<DeviceEvidence> {
        let opts = options.cloned().unwrap_or_default();
        match opts.device_type {
            DeviceType::Tpm => self.get_tpm_evidence(opts.pcr_selection.as_deref()),
        }
    }

    /// Internal: collect evidence from the platform TPM.
    fn get_tpm_evidence(
        &self,
        pcr_selection: Option<&[u32]>,
    ) -> crate::error::Result<DeviceEvidence> {
        let pcrs = match pcr_selection {
            Some(p) => p.to_vec(),
            None => OsInfo::detect()?.pcr_list,
        };

        attestation::ensure_persistent_ak(&self.tpm)?;

        let ak_cert = attestation::get_ak_cert(&self.tpm)?;
        let ak_pub = attestation::get_ak_pub(&self.tpm)?;
        let (quote, sig) = attestation::get_pcr_quote(&self.tpm, &pcrs)?;
        let pcr_values = attestation::get_pcr_values(&self.tpm, &pcrs)?;
        let ek = attestation::get_ephemeral_key(&self.tpm, &pcrs)?;

        // The ephemeral key is a deterministic TPM2 primary — it can be
        // recreated from the same PCRs at any time.  Flush the transient
        // handle now to free TPM object slots; decrypt_token() will
        // recreate it when needed.
        let _ = self.tpm.flush_context(ek.handle);

        let pcr_set: Vec<u32> = pcr_values.iter().map(|(i, _)| *i).collect();
        let pcrs_struct: Vec<PcrEntry> = pcr_values
            .iter()
            .map(|(i, d)| PcrEntry {
                index: *i,
                digest: d.clone(),
            })
            .collect();

        Ok(DeviceEvidence {
            tpm_info: TpmInfo {
                ak_cert,
                ak_pub,
                pcr_quote: quote,
                pcr_sig: sig,
                pcr_set,
                pcrs: pcrs_struct,
                enc_key_pub: ek.public,
                enc_key_certify_info: ek.certify_info,
                enc_key_certify_info_sig: ek.certify_sig,
            },
            pcrs,
        })
    }

    // -----------------------------------------------------------------------
    // Endorsement
    // -----------------------------------------------------------------------

    /// Retrieve an endorsement from the platform metadata service.
    ///
    /// Currently supports [`EndorsementKind::Vcek`] which fetches the AMD
    /// SEV-SNP VCEK certificate chain from Azure THIM / IMDS.
    pub fn get_endorsement(&self, kind: EndorsementKind) -> crate::error::Result<Endorsement> {
        match kind {
            EndorsementKind::Vcek => {
                let imds = guest_attest::ImdsClient::new();
                let chain = imds.get_vcek_chain()?;
                Ok(Endorsement { kind, data: chain })
            }
        }
    }

    // -----------------------------------------------------------------------
    // Report construction
    // -----------------------------------------------------------------------

    /// Build a full guest attestation report from collected artifacts.
    ///
    /// This is a lower-level API for callers who want to collect evidence and
    /// endorsements separately, then assemble the final JSON request body.
    ///
    /// Most callers should use [`attest_guest`](Self::attest_guest) instead.
    pub fn create_attestation_report(
        &self,
        device_evidence: &DeviceEvidence,
        cvm_evidence: Option<&CvmEvidence>,
        endorsement: Option<&Endorsement>,
        options: Option<&AttestOptions>,
    ) -> crate::error::Result<AttestationReport> {
        let os = OsInfo::detect()?;
        let tcg_logs = guest_attest::collect_tcg_logs(&os);
        let client_payload = options
            .and_then(|o| o.client_payload.as_deref())
            .unwrap_or("");

        let isolation = build_isolation_info(cvm_evidence, endorsement)?;

        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: os.os_type,
            os_distro: os.distro,
            os_version_major: os.version_major,
            os_version_minor: os.version_minor,
            os_build: os.build,
            tcg_logs,
            client_payload: client_payload.to_string(),
            tpm_info: device_evidence.tpm_info.clone(),
            isolation,
        };

        let json = params.to_json_string();

        Ok(AttestationReport {
            json,
            pcrs: device_evidence.pcrs.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Attestation
    // -----------------------------------------------------------------------

    /// One-shot guest attestation: collect all artifacts, build the request,
    /// submit to the provider, and return the token.
    ///
    /// Internally this calls [`get_cvm_evidence`](Self::get_cvm_evidence),
    /// [`get_device_evidence`](Self::get_device_evidence), and
    /// [`create_attestation_report`](Self::create_attestation_report) to
    /// assemble the request, then submits it to the provider with retry logic.
    ///
    /// **TrustedLaunch** VMs are automatically detected: when the CVM report
    /// NV index is absent the request carries
    /// [`IsolationType::TrustedLaunch`]
    /// with no TEE evidence.
    ///
    /// Use [`AttestOptions::pcr_selection`] to override the default PCR set.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use azure_guest_attestation_sdk::{AttestationClient, Provider};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = AttestationClient::new()?;
    /// let result = client.attest_guest(Provider::maa("https://..."), None)?;
    /// println!("{}", result.token.unwrap_or_default());
    /// # Ok(())
    /// # }
    /// ```
    pub fn attest_guest(
        &self,
        provider: Provider,
        options: Option<&AttestOptions>,
    ) -> crate::error::Result<AttestResult> {
        let mut timer = guest_attest::StageTimer::new();

        // 1. Resolve PCR selection (explicit > OS default)
        let pcr_selection = options.and_then(|o| o.pcr_selection.clone());
        timer.mark("resolve_pcrs");

        // 2. Try to collect CVM (TEE) evidence.
        //    TrustedLaunch VMs don't have a CVM report NV index, so
        //    get_cvm_evidence() will fail — treat that as TrustedLaunch.
        let cvm_evidence = match self.get_cvm_evidence(None) {
            Ok(ev) => Some(ev),
            Err(e) => {
                tracing::info!(target: "guest_attest", error = %e, "No CVM evidence available, treating as TrustedLaunch");
                None
            }
        };
        timer.mark("cvm_evidence");

        // 3. Collect device evidence (+ ephemeral key handle)
        let dev_opts = DeviceEvidenceOptions {
            device_type: DeviceType::Tpm,
            pcr_selection,
        };
        let device_evidence = self.get_device_evidence(Some(&dev_opts))?;
        timer.mark("device_evidence");

        // 4. Build the attestation report (request JSON)
        let report =
            self.create_attestation_report(&device_evidence, cvm_evidence.as_ref(), None, options)?;
        timer.mark("build_report");

        // 5. Base64url encode and submit to provider
        let encoded = guest_attest::base64_url_encode(report.json.as_bytes());
        let provider_impl = make_provider(&provider);
        let token = guest_attest::submit_to_provider(&encoded, provider_impl.as_ref())?;
        timer.mark("provider_submit");

        Ok(AttestResult {
            token,
            request_json: report.json,
            encoded_request: encoded,
            pcrs: report.pcrs,
        })
    }

    /// TEE-only platform attestation (no TPM / PCR evidence).
    ///
    /// Collects CVM evidence, builds the TEE-only payload (SNP report +
    /// VCEK chain, or TD Quote), and submits directly to a MAA platform
    /// endpoint.
    pub fn attest_platform(&self, provider: Provider) -> crate::error::Result<AttestResult> {
        // Collect CVM evidence with platform quote support
        let opts = CvmEvidenceOptions {
            fetch_platform_quote: true,
            ..Default::default()
        };
        let cvm_evidence = self.get_cvm_evidence(Some(&opts))?;

        match provider {
            Provider::Maa { ref endpoint } => {
                let (payload, rtype) =
                    guest_attest::build_tee_only_payload_from_evidence(&cvm_evidence, None)?;
                let token = guest_attest::submit_tee_only(&payload, endpoint, rtype)?;
                Ok(AttestResult {
                    token: Some(token),
                    request_json: payload,
                    encoded_request: String::new(),
                    pcrs: Vec::new(),
                })
            }
            Provider::Loopback => {
                let (payload, _rtype) =
                    guest_attest::build_tee_only_payload_from_evidence(&cvm_evidence, None)?;
                Ok(AttestResult {
                    token: None,
                    request_json: payload,
                    encoded_request: String::new(),
                    pcrs: Vec::new(),
                })
            }
        }
    }

    /// Decrypt a guest attestation token envelope using the ephemeral key
    /// derived from the given PCR indices.
    ///
    /// The ephemeral RSA key is a deterministic TPM2 primary — it is
    /// recreated from the same PCRs each time, so callers do **not** need
    /// to retain a key handle from [`attest_guest`](Self::attest_guest).
    ///
    /// The `token_b64url` should be the base64url-encoded token returned by
    /// the provider. The `pcrs` should come from the [`AttestResult`] of the
    /// corresponding [`attest_guest`](Self::attest_guest) call.
    pub fn decrypt_token(
        &self,
        pcrs: &[u32],
        token_b64url: &str,
    ) -> crate::error::Result<Option<String>> {
        let handle = self.recreate_ephemeral_key(pcrs)?;
        let result = guest_attest::parse_token(&self.tpm, handle, pcrs, token_b64url);
        let _ = self.tpm.flush_context(handle);
        Ok(result?)
    }

    /// Decrypt raw ciphertext using a TPM ephemeral RSA key derived from the
    /// given PCR indices.
    ///
    /// The ephemeral key is a deterministic TPM2 primary — it is recreated
    /// from the same PCRs each time.  The decryption uses RSAES (PKCS#1 v1.5),
    /// matching the scheme used by Microsoft Azure Attestation (MAA) to
    /// encrypt data to the VM.
    ///
    /// This is a lower-level primitive than [`decrypt_token`](Self::decrypt_token):
    /// it operates on raw RSA ciphertext bytes rather than the full MAA
    /// encrypted token envelope.
    pub fn decrypt_with_tpm_ephemeral_key(
        &self,
        pcrs: &[u32],
        ciphertext: &[u8],
    ) -> crate::error::Result<Vec<u8>> {
        let handle = self.recreate_ephemeral_key(pcrs)?;
        let result = attestation::decrypt_with_ephemeral_key(&self.tpm, handle, pcrs, ciphertext);
        let _ = self.tpm.flush_context(handle);
        Ok(result?)
    }

    /// Recreate the deterministic ephemeral RSA primary key from PCRs and
    /// return its transient handle.  Caller **must** flush the handle when done.
    fn recreate_ephemeral_key(&self, pcrs: &[u32]) -> crate::error::Result<u32> {
        let ek = attestation::get_ephemeral_key(&self.tpm, pcrs)?;
        Ok(ek.handle)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert the public `Provider` enum into a boxed `AttestationProvider` trait object.
fn make_provider(provider: &Provider) -> Box<dyn guest_attest::AttestationProvider> {
    match provider {
        Provider::Maa { endpoint } => Box::new(MaaProvider::new(endpoint)),
        Provider::Loopback => Box::new(guest_attest::LoopbackProvider),
    }
}

/// Build the `IsolationInfo` from CVM evidence and optional endorsement.
///
/// When `evidence` is `None` (TrustedLaunch VMs) the result carries
/// [`IsolationType::TrustedLaunch`] with no TEE evidence.
fn build_isolation_info(
    evidence: Option<&CvmEvidence>,
    endorsement: Option<&Endorsement>,
) -> crate::error::Result<IsolationInfo> {
    let evidence = match evidence {
        Some(ev) => ev,
        None => {
            return Ok(IsolationInfo {
                vm_type: IsolationType::TrustedLaunch,
                evidence: None,
            });
        }
    };
    match evidence.report_type {
        CvmReportType::SnpVmReport => {
            let vcek_chain = match endorsement {
                Some(e) if e.kind == EndorsementKind::Vcek => e.data.clone(),
                _ => {
                    // Auto-fetch if not provided
                    let imds = guest_attest::ImdsClient::new();
                    imds.get_vcek_chain()?
                }
            };
            Ok(IsolationInfo {
                vm_type: IsolationType::SevSnp,
                evidence: Some(IsolationEvidence {
                    tee_proof: TeeProof::Snp {
                        snp_report: evidence.tee_report.clone(),
                        vcek_chain,
                    },
                    runtime_data: evidence.runtime_data.clone(),
                }),
            })
        }
        CvmReportType::TdxVmReport => {
            let td_quote = if !evidence.platform_quote.is_empty() {
                evidence.platform_quote.clone()
            } else {
                // Auto-fetch TD quote
                let imds = guest_attest::ImdsClient::new();
                imds.get_td_quote(&evidence.tee_report)?
            };
            Ok(IsolationInfo {
                vm_type: IsolationType::Tdx,
                evidence: Some(IsolationEvidence {
                    tee_proof: TeeProof::Tdx { td_quote },
                    runtime_data: evidence.runtime_data.clone(),
                }),
            })
        }
        rtype => Err(SdkError::Other(format!(
            "Unsupported report type for attestation: {rtype:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn provider_maa_shorthand() {
        // Full URL — kept as-is
        let p = Provider::maa("https://example.attest.azure.net/attest/SevSnpVm");
        match &p {
            Provider::Maa { endpoint } => {
                assert_eq!(endpoint, "https://example.attest.azure.net/attest/SevSnpVm");
            }
            _ => panic!("expected Maa variant"),
        }
        // Base URL — stored as-is in the enum (resolution happens in MaaProvider::new)
        let p = Provider::maa("https://example.attest.azure.net");
        match &p {
            Provider::Maa { endpoint } => {
                assert_eq!(endpoint, "https://example.attest.azure.net");
            }
            _ => panic!("expected Maa variant"),
        }
    }

    #[test]
    fn provider_loopback() {
        let p = Provider::Loopback;
        assert!(matches!(p, Provider::Loopback));
    }

    #[test]
    fn provider_debug_format() {
        let p = Provider::maa("https://test");
        let s = format!("{p:?}");
        assert!(s.contains("Maa"), "Debug output should contain Maa: {s}");
    }

    #[test]
    fn endorsement_kind_eq() {
        assert_eq!(EndorsementKind::Vcek, EndorsementKind::Vcek);
    }

    #[test]
    fn cvm_evidence_options_default() {
        let opts = CvmEvidenceOptions::default();
        assert!(opts.user_data.is_none());
        assert!(!opts.fetch_platform_quote);
    }

    #[test]
    fn attest_options_default() {
        let opts = AttestOptions::default();
        assert!(opts.client_payload.is_none());
        assert!(opts.pcr_selection.is_none());
    }

    #[test]
    fn device_type_tpm_default() {
        let opts = DeviceEvidenceOptions::default();
        assert_eq!(opts.device_type, DeviceType::Tpm);
        assert!(opts.pcr_selection.is_none());
    }

    #[test]
    fn device_evidence_options_with_pcrs() {
        let opts = DeviceEvidenceOptions {
            device_type: DeviceType::Tpm,
            pcr_selection: Some(vec![0, 1, 7]),
        };
        assert_eq!(opts.pcr_selection.as_ref().unwrap(), &[0, 1, 7]);
    }

    #[test]
    fn cvm_evidence_options_with_user_data() {
        let opts = CvmEvidenceOptions {
            user_data: Some(vec![1, 2, 3]),
            fetch_platform_quote: true,
        };
        assert_eq!(opts.user_data.as_ref().unwrap(), &[1, 2, 3]);
        assert!(opts.fetch_platform_quote);
    }

    #[test]
    fn attest_result_debug_format() {
        let r = AttestResult {
            token: Some("tok".into()),
            request_json: "{}".into(),
            encoded_request: "abc".into(),
            pcrs: vec![0, 1, 7],
        };
        let s = format!("{r:?}");
        assert!(s.contains("tok"));
        assert!(s.contains("[0, 1, 7]"));
    }

    // -----------------------------------------------------------------------
    // build_isolation_info
    // -----------------------------------------------------------------------

    #[test]
    fn build_isolation_info_no_evidence_gives_trusted_launch() {
        let info = build_isolation_info(None, None).unwrap();
        assert!(matches!(info.vm_type, IsolationType::TrustedLaunch));
        assert!(info.evidence.is_none());
    }

    #[test]
    fn build_isolation_info_snp_with_endorsement() {
        let evidence = CvmEvidence {
            report_type: report::CvmReportType::SnpVmReport,
            tee_report: vec![0xAA; report::SNP_VM_REPORT_SIZE],
            runtime_claims: None,
            runtime_data: vec![0xCC; 64],
            platform_quote: vec![],
        };
        let endorsement = Endorsement {
            kind: EndorsementKind::Vcek,
            data: vec![0xDD; 128],
        };
        let info = build_isolation_info(Some(&evidence), Some(&endorsement)).unwrap();
        assert!(matches!(info.vm_type, IsolationType::SevSnp));
        let ev = info.evidence.unwrap();
        match &ev.tee_proof {
            TeeProof::Snp {
                snp_report,
                vcek_chain,
            } => {
                assert_eq!(snp_report, &evidence.tee_report);
                assert_eq!(vcek_chain, &endorsement.data);
            }
            _ => panic!("expected Snp proof"),
        }
        assert_eq!(ev.runtime_data, vec![0xCC; 64]);
    }

    #[test]
    fn build_isolation_info_tdx_with_platform_quote() {
        let td_quote = vec![0xBB; 256];
        let evidence = CvmEvidence {
            report_type: report::CvmReportType::TdxVmReport,
            tee_report: vec![0xAA; report::TDX_VM_REPORT_SIZE],
            runtime_claims: None,
            runtime_data: vec![0xEE; 32],
            platform_quote: td_quote.clone(),
        };
        let info = build_isolation_info(Some(&evidence), None).unwrap();
        assert!(matches!(info.vm_type, IsolationType::Tdx));
        let ev = info.evidence.unwrap();
        match &ev.tee_proof {
            TeeProof::Tdx { td_quote: q } => {
                assert_eq!(q, &td_quote);
            }
            _ => panic!("expected Tdx proof"),
        }
    }

    #[test]
    fn build_isolation_info_unsupported_report_type_returns_error() {
        let evidence = CvmEvidence {
            report_type: report::CvmReportType::VbsVmReport,
            tee_report: vec![],
            runtime_claims: None,
            runtime_data: vec![],
            platform_quote: vec![],
        };
        let err = build_isolation_info(Some(&evidence), None).unwrap_err();
        assert!(
            err.to_string().contains("Unsupported"),
            "expected unsupported error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // build_isolation_info — auto-fetch paths (injectorpp mocked)
    // -----------------------------------------------------------------------

    fn fake_get_vcek_chain(_self: &guest_attest::ImdsClient) -> io::Result<Vec<u8>> {
        Ok(b"mocked-vcek-chain-data".to_vec())
    }

    fn fake_get_td_quote(_self: &guest_attest::ImdsClient, _report: &[u8]) -> io::Result<Vec<u8>> {
        Ok(vec![0xDD; 256])
    }

    #[test]
    fn build_isolation_info_snp_auto_fetch_vcek() {
        use injectorpp::interface::injector::*;
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(
                    guest_attest::ImdsClient::get_vcek_chain
                ))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(fake_get_vcek_chain));
        }

        let evidence = CvmEvidence {
            report_type: report::CvmReportType::SnpVmReport,
            tee_report: vec![0xAA; report::SNP_VM_REPORT_SIZE],
            runtime_claims: None,
            runtime_data: vec![0xCC; 64],
            platform_quote: vec![],
        };
        // No endorsement → triggers IMDS auto-fetch for VCEK chain
        let info = build_isolation_info(Some(&evidence), None).unwrap();
        assert!(matches!(info.vm_type, IsolationType::SevSnp));
        let ev = info.evidence.unwrap();
        match &ev.tee_proof {
            TeeProof::Snp { vcek_chain, .. } => {
                assert_eq!(vcek_chain, b"mocked-vcek-chain-data");
            }
            _ => panic!("expected Snp proof"),
        }
    }

    #[test]
    fn build_isolation_info_tdx_auto_fetch_td_quote() {
        use injectorpp::interface::injector::*;
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(
                    guest_attest::ImdsClient::get_td_quote
                ))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(fake_get_td_quote));
        }

        let evidence = CvmEvidence {
            report_type: report::CvmReportType::TdxVmReport,
            tee_report: vec![0xAA; report::TDX_VM_REPORT_SIZE],
            runtime_claims: None,
            runtime_data: vec![0xEE; 32],
            platform_quote: vec![], // empty → triggers auto-fetch
        };
        let info = build_isolation_info(Some(&evidence), None).unwrap();
        assert!(matches!(info.vm_type, IsolationType::Tdx));
        let ev = info.evidence.unwrap();
        match &ev.tee_proof {
            TeeProof::Tdx { td_quote } => {
                assert_eq!(td_quote, &vec![0xDD; 256]);
            }
            _ => panic!("expected Tdx proof"),
        }
    }

    // -----------------------------------------------------------------------
    // make_provider
    // -----------------------------------------------------------------------

    #[test]
    fn make_provider_maa() {
        let provider = Provider::maa("https://test.attest.azure.net");
        let boxed = make_provider(&provider);
        // Should not panic. MaaProvider is created successfully.
        // We can test via LoopbackProvider to verify trait dispatch works.
        let _ = boxed;
    }

    #[test]
    fn make_provider_loopback_returns_token() {
        let provider = Provider::Loopback;
        let boxed = make_provider(&provider);
        let result = boxed.attest_guest("test_data").unwrap();
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // AttestationReport struct
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_report_debug_format() {
        let r = AttestationReport {
            json: "{\"test\":true}".into(),
            pcrs: vec![0, 7],
        };
        let s = format!("{r:?}");
        assert!(s.contains("test"));
        assert!(s.contains("[0, 7]"));
    }

    // -----------------------------------------------------------------------
    // DeviceEvidence struct
    // -----------------------------------------------------------------------

    #[test]
    fn device_evidence_debug_format() {
        let de = DeviceEvidence {
            tpm_info: TpmInfo {
                ak_cert: vec![],
                ak_pub: vec![],
                pcr_quote: vec![],
                pcr_sig: vec![],
                pcr_set: vec![0],
                pcrs: vec![],
                enc_key_pub: vec![],
                enc_key_certify_info: vec![],
                enc_key_certify_info_sig: vec![],
            },
            pcrs: vec![0, 1],
        };
        let s = format!("{de:?}");
        assert!(s.contains("[0, 1]"));
    }

    // -----------------------------------------------------------------------
    // Endorsement / EndorsementKind
    // -----------------------------------------------------------------------

    #[test]
    fn endorsement_debug_format() {
        let e = Endorsement {
            kind: EndorsementKind::Vcek,
            data: vec![1, 2, 3],
        };
        let s = format!("{e:?}");
        assert!(s.contains("Vcek"));
    }

    #[test]
    fn endorsement_clone() {
        let e = Endorsement {
            kind: EndorsementKind::Vcek,
            data: vec![1, 2, 3],
        };
        let e2 = e.clone();
        assert_eq!(e2.kind, EndorsementKind::Vcek);
        assert_eq!(e2.data, vec![1, 2, 3]);
    }

    // -----------------------------------------------------------------------
    // CvmEvidence
    // -----------------------------------------------------------------------

    #[test]
    fn cvm_evidence_debug_format() {
        let ev = CvmEvidence {
            report_type: report::CvmReportType::SnpVmReport,
            tee_report: vec![0xAA],
            runtime_claims: None,
            runtime_data: vec![],
            platform_quote: vec![],
        };
        let s = format!("{ev:?}");
        assert!(s.contains("SnpVmReport"));
    }

    #[test]
    fn cvm_evidence_clone() {
        let ev = CvmEvidence {
            report_type: report::CvmReportType::TdxVmReport,
            tee_report: vec![1, 2],
            runtime_claims: None,
            runtime_data: vec![3, 4],
            platform_quote: vec![5],
        };
        let ev2 = ev.clone();
        assert_eq!(ev2.report_type, report::CvmReportType::TdxVmReport);
        assert_eq!(ev2.tee_report, vec![1, 2]);
        assert_eq!(ev2.platform_quote, vec![5]);
    }
}
