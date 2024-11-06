/** @file
    Private includes for Vmbus EFI driver.

    Copyright (c) Microsoft Corporation.
    SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#pragma once

#include <Protocol/DevicePath.h>
#include <Protocol/EfiHv.h>
#include <Protocol/Vmbus.h>
#include <Library/CrashLib.h>

//
// Disable warnings for nameless unions/structs.
//
#pragma warning(push)
#pragma warning(disable : 4201)

//
// Definitions needed for ChannelMessages.h
//
#define MAXIMUM_SYNIC_MESSAGE_BYTES 240
#define MAX_USER_DEFINED_BYTES 120

typedef struct _GPA_RANGE
{
    UINT32  ByteCount;
    UINT32  ByteOffset;
    UINT64  PfnArray[1];

} GPA_RANGE;

#include <ChannelMessages.h>

#define VMBUS_MESSAGE_CONNECTION_ID 1
#define VMBUS_MESSAGE_TYPE 1

#define VMBUS_ROOT_NODE_HID_STR "VMBus"

#define EFI_VMBUS_CHANNEL_DEVICE_PATH_GUID \
    {0x9b17e5a2, 0x891, 0x42dd, {0xb6, 0x53, 0x80, 0xb5, 0xc2, 0x28, 0x9, 0xba}}

extern EFI_HV_PROTOCOL *mHv;
extern EFI_HV_IVM_PROTOCOL *mHvIvm;
extern UINTN mSharedGpaBoundary;
extern UINT64 mCanonicalizationMask;

extern EFI_GUID gEfiVmbusChannelDevicePathGuid;

//
// A tag GUID for the VMBus bus controller. The UEFI driver model requires
// bus children to consume a protocol from the bus controller for child tracking
// purposes, so we give the VMBus channels a dummy tag protocol to consume.
//
extern EFI_GUID gEfiVmbusRootProtocolGuid;

typedef struct
{
    ACPI_EXTENDED_HID_DEVICE_PATH AcpiExtendedNode;
    CHAR8 HidStr[sizeof(VMBUS_ROOT_NODE_HID_STR)];
    CHAR8 UidStr[1];
    CHAR8 CidStr[1];

} VMBUS_ROOT_NODE;

typedef struct
{
    VMBUS_ROOT_NODE VmbusRootNode;
    EFI_DEVICE_PATH_PROTOCOL End;

} VMBUS_ROOT_DEVICE_PATH;

typedef struct
{
    VMBUS_ROOT_NODE VmbusRootNode;
    VMBUS_DEVICE_PATH VmbusChannelNode;
    EFI_DEVICE_PATH_PROTOCOL End;

} VMBUS_CHANNEL_DEVICE_PATH;

extern VMBUS_ROOT_NODE gVmbusRootNode;
extern VMBUS_DEVICE_PATH gVmbusChannelNode;
extern EFI_DEVICE_PATH_PROTOCOL gEfiEndNode;

#define TPL_VMBUS (TPL_HIGH_LEVEL - 1)
#define VMBUS_MAX_GPADLS 256
#define VMBUS_MAX_CHANNELS HV_EVENT_FLAGS_COUNT

typedef struct _VMBUS_MESSAGE
{
    UINT32 Size;

    union
    {
        UINT8 Data[MAXIMUM_SYNIC_MESSAGE_BYTES];
        VMBUS_CHANNEL_MESSAGE_HEADER Header;
        VMBUS_CHANNEL_OFFER_CHANNEL OfferChannel;
        VMBUS_CHANNEL_RESCIND_OFFER RescindOffer;
        VMBUS_CHANNEL_OPEN_CHANNEL OpenChannel;
        VMBUS_CHANNEL_OPEN_RESULT OpenResult;
        VMBUS_CHANNEL_CLOSE_CHANNEL CloseChannel;
        VMBUS_CHANNEL_GPADL_HEADER GpadlHeader;
        VMBUS_CHANNEL_GPADL_BODY GpadlBody;
        VMBUS_CHANNEL_GPADL_CREATED GpadlCreated;
        VMBUS_CHANNEL_GPADL_TEARDOWN GpadlTeardown;
        VMBUS_CHANNEL_GPADL_TORNDOWN GpadlTorndown;
        VMBUS_CHANNEL_RELID_RELEASED RelIdReleased;
        VMBUS_CHANNEL_INITIATE_CONTACT InitiateContact;
        VMBUS_CHANNEL_VERSION_RESPONSE VersionResponse;
    };

} VMBUS_MESSAGE;

typedef struct _VMBUS_MESSAGE_RESPONSE
{
    EFI_EVENT Event;
    VMBUS_MESSAGE Message;

} VMBUS_MESSAGE_RESPONSE;

#define VMBUS_DRIVER_VERSION 0x10
#define VMBUS_ROOT_CONTEXT_SIGNATURE         SIGNATURE_32('v','m','b','r')

typedef struct _VMBUS_ROOT_CONTEXT VMBUS_ROOT_CONTEXT;

#define VMBUS_CHANNEL_CONTEXT_SIGNATURE         SIGNATURE_32('v','m','b','c')

typedef struct _VMBUS_CHANNEL_CONTEXT
{
    UINT32 Signature;

    EFI_HANDLE Handle;
    EFI_VMBUS_LEGACY_PROTOCOL LegacyVmbusProtocol;
    EFI_VMBUS_PROTOCOL VmbusProtocol;
    VMBUS_CHANNEL_DEVICE_PATH DevicePath;
    LIST_ENTRY Link;
    UINT32 ChannelId;
    HV_CONNECTION_ID ConnectionId;
    VMBUS_ROOT_CONTEXT *RootContext;
    VMBUS_MESSAGE_RESPONSE Response;

    //
    // Interrupt events are managed by the root device.
    //
    EFI_EVENT Interrupt;

    //
    // A confidential channel is a channel offered by the paravisor on a
    // hardware-isolated VM, which means it can use encrypted memory for the
    // ring buffer.
    //
    BOOLEAN Confidential;

} VMBUS_CHANNEL_CONTEXT;

struct _EFI_VMBUS_GPADL
{
    VOID* AllocatedBuffer;
    UINT64 VisibleBufferPA;
    UINT32 BufferLength;
    UINT32 NumberOfPages;
    UINT32 GpadlHandle;
    EFI_HV_PROTECTION_HANDLE ProtectionHandle;
    BOOLEAN Legacy;
};

VMBUS_MESSAGE*
VmbusRootWaitForChannelResponse(
    IN  VMBUS_CHANNEL_CONTEXT *ChannelContext
    );

EFI_STATUS
VmbusRootWaitForGpadlResponse(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    IN  UINT32 GpadlHandle,
    OUT VMBUS_MESSAGE **Message
    );

VOID
VmbusRootInitializeMessage(
    IN OUT  VMBUS_MESSAGE *Message,
    IN      VMBUS_CHANNEL_MESSAGE_TYPE Type,
    IN      UINT32 Size
    );

EFI_STATUS
VmbusRootSendMessage(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    IN  VMBUS_MESSAGE *Message
    );

EFI_STATUS
VmbusRootGetFreeGpadl(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    OUT UINT32 *GpadlHandle
    );

VOID
VmbusRootReclaimGpadl(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    IN  UINT32 GpadlHandle
    );

VOID
VmbusRootSetGpadlPageRange(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    IN  UINT32 GpadlHandle,
    IN  UINT64 GpaPageBase,
    IN  UINT32 PageCount
    );

BOOLEAN
VmbusRootValidateGpadl(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    IN  UINT32 GpadlHandle
    );

VOID
VmbusRootSetInterruptEntry(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    IN  UINT32 ChannelId,
    IN  EFI_EVENT Event
    );

VOID
VmbusRootClearInterruptEntry(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    IN  UINT32 ChannelId
    );

VOID
VmbusChannelInitializeContext(
    IN OUT  VMBUS_CHANNEL_CONTEXT *ChannelContext,
    IN      VMBUS_CHANNEL_OFFER_CHANNEL *Offer,
    IN      VMBUS_ROOT_CONTEXT *RootContext
    );

VOID
VmbusChannelDestroyContext(
    IN  VMBUS_CHANNEL_CONTEXT *ChannelContext
    );

BOOLEAN
VmbusRootSupportsFeatureFlag(
    IN  VMBUS_ROOT_CONTEXT *RootContext,
    IN  UINT32 FeatureFlag
    );

#pragma warning(pop)

