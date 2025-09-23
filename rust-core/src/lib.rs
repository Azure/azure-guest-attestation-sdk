//! Minimal Rust core skeleton for Azure CVM Attestation SDK.
//!
//! This crate is compiled as a `cdylib` and exposes a small C-compatible ABI.

use std::ptr;
use std::slice;
use libc::{c_int, size_t};

#[repr(C)]
pub struct AzureCvmAttestationContext {
    _private: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum AzureCvmReportType {
    CVM_REPORT_TYPE_INVALID = 0,
    CVM_REPORT_TYPE_RESERVED = 1,
    CVM_REPORT_TYPE_SNP = 2,
    CVM_REPORT_TYPE_TVM = 3,
    CVM_REPORT_TYPE_TDX = 4,
}

// --- Context management ----------------------------------------------------

#[no_mangle]
pub extern "C" fn azure_cvm_attestation_create() -> *mut AzureCvmAttestationContext {
    let ctx = Box::new(AzureCvmAttestationContext { _private: 0 });
    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "C" fn azure_cvm_attestation_free(ctx: *mut AzureCvmAttestationContext) {
    if ctx.is_null() {
        return;
    }
    unsafe { Box::from_raw(ctx); }
}

// --- Report type ----------------------------------------------------------

#[no_mangle]
pub extern "C" fn azure_cvm_attestation_get_report_type(_ctx: *mut AzureCvmAttestationContext) -> AzureCvmReportType {
    // Stub: return SNP by default
    AzureCvmReportType::CVM_REPORT_TYPE_SNP
}

// --- Evidence access ------------------------------------------------------

#[no_mangle]
pub extern "C" fn azure_cvm_attestation_get_hardware_report(
    _ctx: *mut AzureCvmAttestationContext,
    hw_buf: *mut *mut u8,
    hw_len: *mut size_t,
) -> c_int {
    if hw_buf.is_null() || hw_len.is_null() {
        return -1;
    }

    let data = b"stub-hw-report";
    unsafe {
        let len = data.len() as size_t;
        let ptr = libc::malloc(len) as *mut u8;
        if ptr.is_null() {
            return -1;
        }
        ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        *hw_buf = ptr;
        *hw_len = len;
    }

    0
}

#[no_mangle]
pub extern "C" fn azure_cvm_attestation_get_runtime_data(
    _ctx: *mut AzureCvmAttestationContext,
    rt_buf: *mut *mut u8,
    rt_len: *mut size_t,
) -> c_int {
    if rt_buf.is_null() || rt_len.is_null() {
        return -1;
    }

    let data = b"stub-runtime-data";
    unsafe {
        let len = data.len() as size_t;
        let ptr = libc::malloc(len) as *mut u8;
        if ptr.is_null() {
            return -1;
        }
        ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        *rt_buf = ptr;
        *rt_len = len;
    }

    0
}

#[no_mangle]
pub extern "C" fn azure_cvm_attestation_get_hardware_evidence(
    ctx: *mut AzureCvmAttestationContext,
    hw_buf: *mut *mut u8,
    hw_len: *mut size_t,
    rt_buf: *mut *mut u8,
    rt_len: *mut size_t,
) -> c_int {
    let rc1 = azure_cvm_attestation_get_hardware_report(ctx, hw_buf, hw_len);
    if rc1 != 0 {
        return rc1;
    }
    let rc2 = azure_cvm_attestation_get_runtime_data(ctx, rt_buf, rt_len);
    if rc2 != 0 {
        // free hw_buf on failure
        unsafe { libc::free(*hw_buf as *mut libc::c_void); }
        return rc2;
    }
    0
}

// --- Report refresh ------------------------------------------------------

#[no_mangle]
pub extern "C" fn azure_cvm_attestation_refresh(_ctx: *mut AzureCvmAttestationContext) -> c_int {
    // Stub: nothing to refresh in skeleton
    0
}

// --- Utility: free buffer created by SDK ---------------------------------

#[no_mangle]
pub extern "C" fn azure_cvm_attestation_free_buffer(buf: *mut u8) {
    if buf.is_null() { return; }
    unsafe { libc::free(buf as *mut libc::c_void); }
}
