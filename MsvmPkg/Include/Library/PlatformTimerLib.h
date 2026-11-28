/** @file
  Loader-supplied X64 timer configuration available before PEI services.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#pragma once

#include <Uefi.h>
#include <BiosInterface.h>

EFI_STATUS
EFIAPI
ParsePlatformTimerInformation (
  IN CONST VOID                         *ConfigBlob,
  IN UINTN                              AvailableSize,
  OUT UEFI_CONFIG_X64_TIMER_INFORMATION  *Information
  );

// NULL selects the normal Hyper-V profile. Unenlightened X64 requires
// a valid loader record; missing or malformed input fails explicitly.
CONST UEFI_CONFIG_X64_TIMER_INFORMATION *
EFIAPI
GetPlatformTimerInformation (
  VOID
  );
