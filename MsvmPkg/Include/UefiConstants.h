/** @file

    This file contains constants used in UEFI.

    Copyright (c) Microsoft Corporation.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#if defined (MDE_CPU_X64)
#define MISC_PAGE_COUNT_PAGE_TABLES  6
#define MISC_PAGE_COUNT_GDT_ENTRIES  1
#define MISC_PAGE_COUNT_FREE_RW      2
#define MISC_PAGE_COUNT_TOTAL        (MISC_PAGE_COUNT_PAGE_TABLES + MISC_PAGE_COUNT_GDT_ENTRIES + MISC_PAGE_COUNT_FREE_RW)
#define MISC_PAGE_OFFSET_FREE_RW     (MISC_PAGE_COUNT_PAGE_TABLES + MISC_PAGE_COUNT_GDT_ENTRIES)
#endif

enum {
  ConfigLibConsoleModeDefault = 0,   // video+kbd (having a head)
  ConfigLibConsoleModeCOM1    = 1,   // headless with COM1 serial console
  ConfigLibConsoleModeCOM2    = 2,   // headless with COM2 serial console
  ConfigLibConsoleModeNone    = 3    // headless
};

enum {
  ConfigLibMemoryProtectionModeDisabled = 0,   // MEMORY_PROTECTION_SETTINGS_OFF
  ConfigLibMemoryProtectionModeDefault  = 1,   // MEMORY_PROTECTION_SETTINGS_SHIP_MODE
  ConfigLibMemoryProtectionModeStrict   = 2,   // MEMORY_PROTECTION_SETTINGS_DEBUG
  ConfigLibMemoryProtectionModeRelaxed  = 3,   // MEMORY_PROTECTION_SETTINGS_SHIP_MODE with fewer checks
};
