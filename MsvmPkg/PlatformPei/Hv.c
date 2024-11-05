/** @file
  Hypervisor interactions during PEI.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>

#include <Platform.h>
#include <Hv.h>
#include <IsolationTypes.h>

#include <Hv/HvGuestCpuid.h>
#include <Library/DebugLib.h>
#include <Library/CrashDumpAgentLib.h>

BOOLEAN mParavisorPresent = FALSE;
UINT32 mIsolationType = UefiIsolationTypeNone;
UINT32 mSharedGpaBit = 0;

VOID
HvDetectIsolation(
    VOID
    )
/*++

Routine Description:

    Determines whether UEFI is running in an isolated VM.

Arguments:

    None.

Return Value:

    None.

--*/
{
#if defined(MDE_CPU_X64)

    HV_CPUID_RESULT cpuidResult;
    UINT64 sharedGpaBoundary;
    UINT64 sharedGpaCanonicalizationBitmask;
    EFI_STATUS status = EFI_SUCCESS;
    UINT32 virtualAddressBits;

    AsmCpuid(HvCpuIdFunctionVersionAndFeatures, &cpuidResult.Eax, &cpuidResult.Ebx, &cpuidResult.Ecx, &cpuidResult.Edx);
    if (!cpuidResult.VersionAndFeatures.HypervisorPresent)
    {
        DEBUG((DEBUG_INFO, "%a - Hypervisor is not present \n", __FUNCTION__));
        return;
    }

    AsmCpuid(HvCpuIdFunctionHvInterface, &cpuidResult.Eax, &cpuidResult.Ebx, &cpuidResult.Ecx, &cpuidResult.Edx);
    if (cpuidResult.HvInterface.Interface != HvMicrosoftHypervisorInterface)
    {
        DEBUG((DEBUG_INFO, "%a - Hypervisor interface is not present \n", __FUNCTION__));
        return;
    }

    AsmCpuid(HvCpuIdFunctionMsHvFeatures, &cpuidResult.Eax, &cpuidResult.Ebx, &cpuidResult.Ecx, &cpuidResult.Edx);
    if (!cpuidResult.MsHvFeatures.PartitionPrivileges.Isolation)
    {
        DEBUG((DEBUG_INFO, "%a - Isolation is not present \n", __FUNCTION__));
        return;
    }

    AsmCpuid(HvCpuidFunctionMsHvIsolationConfiguration, &cpuidResult.Eax, &cpuidResult.Ebx, &cpuidResult.Ecx, &cpuidResult.Edx);
    switch (cpuidResult.MsHvIsolationConfiguration.IsolationType)
    {
    case HV_PARTITION_ISOLATION_TYPE_VBS:
        { STATIC_ASSERT(HV_PARTITION_ISOLATION_TYPE_VBS == UefiIsolationTypeVbs, "invalid definition"); }
        mIsolationType = UefiIsolationTypeVbs;
        break;
    case HV_PARTITION_ISOLATION_TYPE_SNP:
        { STATIC_ASSERT(HV_PARTITION_ISOLATION_TYPE_SNP == UefiIsolationTypeSnp, "invalid definition"); }
        mIsolationType = UefiIsolationTypeSnp;
        break;
    case HV_PARTITION_ISOLATION_TYPE_TDX:
        { STATIC_ASSERT(HV_PARTITION_ISOLATION_TYPE_TDX == UefiIsolationTypeTdx, "invalid definition"); }
        mIsolationType = UefiIsolationTypeTdx;
        break;
    case HV_PARTITION_ISOLATION_TYPE_NONE:
        { STATIC_ASSERT(HV_PARTITION_ISOLATION_TYPE_NONE == UefiIsolationTypeNone, "invalid definition"); }
        return;
    default:
        ASSERT(FALSE);
        return;
    }

    status = PcdSet32S(PcdIsolationArchitecture, mIsolationType);
    if (EFI_ERROR(status))
    {
        DEBUG((DEBUG_ERROR, "Failed to set the PCD PcdIsolationArchitecture::0x%x \n", status));
        PEI_FAIL_FAST_IF_FAILED(status);
    }

    if (cpuidResult.MsHvIsolationConfiguration.ParavisorPresent)
    {
        mParavisorPresent = TRUE;
        status = PcdSetBoolS(PcdIsolationParavisorPresent, TRUE);
        if (EFI_ERROR(status))
        {
            DEBUG((DEBUG_ERROR, "Failed to set the PCD PcdIsolationParavisorPresent::0x%x \n", status));
            PEI_FAIL_FAST_IF_FAILED(status);
        }
    }

    if (cpuidResult.MsHvIsolationConfiguration.SharedGpaBoundaryActive)
    {
        mSharedGpaBit = cpuidResult.MsHvIsolationConfiguration.SharedGpaBoundaryBits;
        sharedGpaBoundary = 1ull << mSharedGpaBit;
        sharedGpaCanonicalizationBitmask = 0;
        virtualAddressBits = 48;
        if (cpuidResult.MsHvIsolationConfiguration.SharedGpaBoundaryBits == (virtualAddressBits - 1))
        {
            sharedGpaCanonicalizationBitmask = ~((1ull << virtualAddressBits) - 1);
        }
        else if (cpuidResult.MsHvIsolationConfiguration.SharedGpaBoundaryBits > (virtualAddressBits - 1))
        {
            FAIL_FAST_UNEXPECTED_HOST_BEHAVIOR();
        }

        DEBUG((DEBUG_VERBOSE,
               "%a: SharedGpaBoundary: 0x%lx, CanonicalizationMask 0x%lx\n",
               __FUNCTION__,
               sharedGpaBoundary,
               sharedGpaCanonicalizationBitmask));

        status = PcdSet64S(PcdIsolationSharedGpaBoundary, sharedGpaBoundary);
        if (!EFI_ERROR(status))
        {
            status = PcdSet64S(PcdIsolationSharedGpaCanonicalizationBitmask,
                               sharedGpaCanonicalizationBitmask);
        }

        if (EFI_ERROR(status))
        {
            DEBUG((DEBUG_ERROR, "Failed to set the PCD PcdIsolationSharedGpaBoundary::0x%x \n", status));
            PEI_FAIL_FAST_IF_FAILED(status);
        }
    }

#endif
    return;
}

VOID
HvDetectSvsm(
    IN  VOID            *OpaqueSecretsPage,
    OUT UINT64          *SvsmBase,
    OUT UINT64          *SvsmSize
    )
/*++

Routine Description:

    Determines whether an SVSM is present.

Arguments:

    SecretsPage - A pointer to the SNP secrets page, if this is a no-paravisor
                  SNP system.

    SvsmBase - Receives the base of the SVSM area.

    SvsmSize - Receives the size of the SVSM area.

Return Value:

    None.

--*/
{
    EFI_STATUS status;
    PSNP_SECRETS SecretsPage = OpaqueSecretsPage;

    //
    // Examine the secrets page to determine whether any SVSM has declared its
    // presence.
    //

    if (SecretsPage->SvsmSize != 0)
    {
        *SvsmBase = SecretsPage->SvsmBase;
        *SvsmSize = SecretsPage->SvsmSize;
        status = PcdSet64S(PcdSvsmCallingArea, SecretsPage->SvsmCallingArea);
        if (EFI_ERROR(status))
        {
            DEBUG((DEBUG_ERROR, "Failed to set the SVSM calling area address::0x%x \n", status));
            PEI_FAIL_FAST_IF_FAILED(status);
        }
    }
    else
    {
        *SvsmBase = 0;
        *SvsmSize = 0;
    }
}
