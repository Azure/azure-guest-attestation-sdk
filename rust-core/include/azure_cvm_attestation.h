#ifndef AZURE_CVM_ATTESTATION_H
#define AZURE_CVM_ATTESTATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum AzureCvmReportType {
    CVM_REPORT_TYPE_INVALID = 0,
    CVM_REPORT_TYPE_RESERVED = 1,
    CVM_REPORT_TYPE_SNP = 2,
    CVM_REPORT_TYPE_TVM = 3,
    CVM_REPORT_TYPE_TDX = 4,
} AzureCvmReportType;

typedef struct AzureCvmAttestationContext AzureCvmAttestationContext;

// Context management
AzureCvmAttestationContext* azure_cvm_attestation_create();
void azure_cvm_attestation_free(AzureCvmAttestationContext* ctx);

// Evidence access
AzureCvmReportType azure_cvm_attestation_get_report_type(AzureCvmAttestationContext* ctx);
int azure_cvm_attestation_get_hardware_report(AzureCvmAttestationContext* ctx, uint8_t** hw_buf, size_t* hw_len);
int azure_cvm_attestation_get_runtime_data(AzureCvmAttestationContext* ctx, uint8_t** rt_buf, size_t* rt_len);
int azure_cvm_attestation_get_hardware_evidence(AzureCvmAttestationContext* ctx, uint8_t** hw_buf, size_t* hw_len, uint8_t** rt_buf, size_t* rt_len);
int azure_cvm_attestation_refresh(AzureCvmAttestationContext* ctx);

// Free buffers allocated by the SDK
void azure_cvm_attestation_free_buffer(uint8_t* buf);

#ifdef __cplusplus
}
#endif

#endif // AZURE_CVM_ATTESTATION_H
