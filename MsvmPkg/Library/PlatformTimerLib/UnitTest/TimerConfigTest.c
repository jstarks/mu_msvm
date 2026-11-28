/** @file
  Host-only tests of the firmware's early loader timer parser.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/PlatformTimerLib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

int
main (
  void
  )
{
  struct {
    UEFI_CONFIG_STRUCTURE_COUNT        Count;
    UEFI_CONFIG_X64_TIMER_INFORMATION  Timer;
  } Blob = {
    { { UefiConfigStructureCount, sizeof (UEFI_CONFIG_STRUCTURE_COUNT) }, 2, 40 },
    { { UefiConfigX64TimerInformation, sizeof (UEFI_CONFIG_X64_TIMER_INFORMATION) },
      2400000000ULL, 100000000, 0 }
  };
  UEFI_CONFIG_X64_TIMER_INFORMATION  Output;
  UEFI_CONFIG_X64_TIMER_INFORMATION  Before;
  UINT64                            Frequencies[] = { 0, 9999999, 10000001 };

  _Static_assert (sizeof (Blob) == 40, "early timer wire layout");
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_SUCCESS);
  assert (Output.TscFrequency == 2400000000ULL);
  assert (Output.ApicFrequency == 100000000);
  Blob.Timer.TscFrequency = 3000000000ULL;
  Blob.Timer.ApicFrequency = 1000000000;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_SUCCESS);
  assert (Output.TscFrequency == 3000000000ULL);
  assert (Output.ApicFrequency == 1000000000);

  memset (&Output, 0xa5, sizeof (Output));
  Before = Output;
  for (UINTN Size = 0; Size < sizeof (Blob); Size++) {
    assert (ParsePlatformTimerInformation (&Blob, Size, &Output) == EFI_INVALID_PARAMETER);
    assert (memcmp (&Output, &Before, sizeof (Output)) == 0);
  }

  Blob.Count.Header.Length = 8;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_INVALID_PARAMETER);
  Blob.Count.Header.Length = 16;
  Blob.Count.TotalConfigBlobSize = 39;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_INVALID_PARAMETER);
  Blob.Count.TotalConfigBlobSize = 40;
  Blob.Count.TotalStructureCount = 1;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_INVALID_PARAMETER);
  Blob.Count.TotalStructureCount = 2;
  Blob.Timer.Header.Type = UefiConfigBiosInformation;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_NOT_FOUND);
  Blob.Timer.Header.Type = UefiConfigX64TimerInformation;
  Blob.Timer.Header.Length = 32;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_INVALID_PARAMETER);
  Blob.Timer.Header.Length = 24;
  Blob.Timer.Reserved = 1;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_INVALID_PARAMETER);
  Blob.Timer.Reserved = 0;
  Blob.Timer.ApicFrequency = 0;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_INVALID_PARAMETER);
  Blob.Timer.ApicFrequency = 1;
  for (UINTN Index = 0; Index < sizeof (Frequencies) / sizeof (Frequencies[0]); Index++) {
    Blob.Timer.TscFrequency = Frequencies[Index];
    assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_INVALID_PARAMETER);
  }
  assert (memcmp (&Output, &Before, sizeof (Output)) == 0);

  Blob.Timer.TscFrequency = 10000000;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_SUCCESS);
  Blob.Count.TotalConfigBlobSize = 4096;
  assert (ParsePlatformTimerInformation (&Blob, sizeof (Blob), &Output) == EFI_SUCCESS);
  puts ("Early timer configuration tests passed");
  return 0;
}
