/** @file
  Validate the early timer configuration prefix without PEI services.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/PlatformTimerLib.h>

EFI_STATUS
EFIAPI
ParsePlatformTimerInformation (
  IN CONST VOID                         *ConfigBlob,
  IN UINTN                              AvailableSize,
  OUT UEFI_CONFIG_X64_TIMER_INFORMATION  *Information
  )
{
  CONST UEFI_CONFIG_STRUCTURE_COUNT        *Count;
  CONST UEFI_CONFIG_X64_TIMER_INFORMATION  *Timer;
  UINTN                                   PrefixSize;

  PrefixSize = sizeof (*Count) + sizeof (*Timer);
  if (AvailableSize < sizeof (*Count)) {
    return EFI_INVALID_PARAMETER;
  }

  Count = ConfigBlob;
  if ((Count->Header.Type != UefiConfigStructureCount) ||
      (Count->Header.Length != sizeof (*Count)) ||
      (Count->TotalStructureCount < 2) ||
      (Count->TotalConfigBlobSize < PrefixSize) ||
      (AvailableSize < PrefixSize))
  {
    return EFI_INVALID_PARAMETER;
  }

  Timer = (CONST VOID *)((CONST UINT8 *)ConfigBlob + sizeof (*Count));
  if (Timer->Header.Type != UefiConfigX64TimerInformation) {
    return EFI_NOT_FOUND;
  }

  if ((Timer->Header.Length != sizeof (*Timer)) ||
      (Timer->Reserved != 0) ||
      (Timer->TscFrequency < 10000000) ||
      ((Timer->TscFrequency % 10000000) != 0) ||
      (Timer->ApicFrequency == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  *Information = *Timer;
  return EFI_SUCCESS;
}
