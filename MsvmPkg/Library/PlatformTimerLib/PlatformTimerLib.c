/** @file
  Select the X64 timer profile from immutable loader input.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/PlatformTimerLib.h>
#include <UefiConstants.h>

STATIC BOOLEAN                            mInitialized;
STATIC BOOLEAN                            mGeneric;
STATIC UEFI_CONFIG_X64_TIMER_INFORMATION  mInformation;

CONST UEFI_CONFIG_X64_TIMER_INFORMATION *
EFIAPI
GetPlatformTimerInformation (
  VOID
  )
{
  UINT32      Features;
  UINT32      Interface;
  UINT64      ConfigAddress;
  EFI_STATUS  Status;

  if (!mInitialized) {
    AsmCpuid (1, NULL, NULL, &Features, NULL);
    Interface = 0;
    if ((Features & BIT31) != 0) {
      AsmCpuid (0x40000001, &Interface, NULL, NULL, NULL);
    }

    if (Interface != SIGNATURE_32 ('H', 'v', '#', '1')) {
      ConfigAddress = FixedPcdGet64 (PcdFdBaseAddress) +
                      FixedPcdGet32 (PcdFdSize) +
                      SIZE_4KB * MISC_PAGE_COUNT_TOTAL;
      Status = ParsePlatformTimerInformation (
                 (CONST VOID *)(UINTN)ConfigAddress,
                 sizeof (UEFI_CONFIG_STRUCTURE_COUNT) + sizeof (mInformation),
                 &mInformation
                 );
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "Unenlightened X64 requires valid loader timer information: %r\n", Status));
        CpuDeadLoop ();
      }

      mGeneric = TRUE;
    }

    mInitialized = TRUE;
  }

  return mGeneric ? &mInformation : NULL;
}
