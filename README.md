# Project

This repo contains the Msvm firmware project for virtual machines running with
the Microsoft hypervisor.

This repository is built on top of Project Mu.  Please see Project Mu for details https://microsoft.github.io/mu

## Developer Guide

See the [developer guide](MsvmPkg/Docs/DEVGUIDE.md) and in particular the getting started section.

## Firmware Artifacts

Patina and Legacy C Core CI names firmware artifacts using this case-sensitive format:

```text
firmware-<TARGET>-<ARCH>-<TOOLCHAIN>[-legacy]
```

GitHub release assets use the same name with a `.tar.gz` suffix. Consumers such as
OpenVMM should select an exact asset name from a specific release tag. For example:

```text
firmware-RELEASE-X64-CLANGPDB.tar.gz
firmware-RELEASE-X64-CLANGPDB-legacy.tar.gz
```

The Rust Patina DXE core is the default and uses the unsuffixed name. The legacy
C DXE core adds `-legacy`;
the brackets above indicate an optional suffix and are not part of the name.
`TOOLCHAIN` identifies the EDK II toolchain; the Patina core is supplied as a
prebuilt dependency. Both `DEBUG` and `RELEASE` targets are built for each of these
combinations:

| Architecture | Toolchain | DXE Core |
| --- | --- | --- |
| X64 | CLANGPDB | C, Patina |
| AARCH64 | CLANGPDB | C, Patina |

Each firmware archive contains `FV/MSVM.fd` and the `MAP/` and `PDB/` symbol
directories. CI build logs use the same variant suffix with a `logs-` prefix and
are not included in releases. Releases are published after successful main-branch
push validation, including OpenVMM boot tests of all X64 variants.

Unsuffixed assets now contain Patina instead of the C core. Consumers that need
the C core must add `-legacy` to their asset selection for new releases. Consumers
using the former `-patina` suffix should switch to the unsuffixed names. Consumers
using boolean-suffixed names must also update their selection for new releases.
Existing release assets retain their names. Archive contents are unchanged.

## Experimental Unenlightened X64 Timers

The legacy C core can use loader-supplied TSC and local APIC frequencies instead
of the Hyper-V reference counter and SynIC timer. Build one image without a
frequency-specific macro:

```text
stuart_build -c MsvmPkg/PlatformBuild.py TARGET=RELEASE TOOL_CHAIN_TAG=CLANGPDB BLD_*_USE_LEGACY_C_CORE=TRUE
```

The loader places `UEFI_CONFIG_X64_TIMER_INFORMATION` (type `0x29`, 24 bytes)
immediately after the configuration blob's `StructureCount` record. It contains
a 64-bit TSC frequency, a 32-bit undivided local APIC frequency, and a zero
reserved field. Both frequencies are in Hz and must match the platform. TSC
must be at least 10 MHz and an exact multiple of 10 MHz; APIC must be nonzero.
The firmware validates and captures these inputs without PEI services.

OpenVMM queries the guest-visible clocks from its `virt` backend and supplies
this record automatically:

```text
--hypervisor strudel --no-hv --no-vmbus --uefi firmware=path/to/MSVM.fd
```

Strudel reports a 1 GHz TSC and a 100 MHz undivided local APIC clock. Backends
that cannot report both clocks cannot use this unenlightened profile.
The record requires firmware interface 2.1 and the
`MSVM_FIRMWARE_VERSION_FLAG_X64_TIMER_CONFIG` capability. Only X64 legacy-C
builds advertise that capability. Hyper-V launches retain their reference
counter and SynIC timer, with no timer record. Unenlightened X64 fails explicitly
when its clock input is missing or malformed. The old
`BLD_*_GENERIC_TSC_FREQUENCY` build option has been removed.
This remains a bring-up profile, not general PC support or a boot qualification.

The local APIC driver and nested interrupt/TPL support retain their BSD notices
and come from EDK2 commit `17f52bba035cfa5a18b8a8bf3e88e46bcb0da069`.

The early parser has host-only tests. On ARM64 Linux, run:

```bash
clang -std=c11 -Wall -Wextra -Werror -fshort-wchar \
  -I MU_BASECORE/MdePkg/Include -I MU_BASECORE/MdePkg/Include/AArch64 \
  -I MsvmPkg/Include MsvmPkg/Library/PlatformTimerLib/Parse.c \
  MsvmPkg/Library/PlatformTimerLib/UnitTest/TimerConfigTest.c -o /tmp/timer-config-tests
/tmp/timer-config-tests
```

## Contributing

This project welcomes [contributions](MsvmPkg/Docs/CONTRIBUTING.md) and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

