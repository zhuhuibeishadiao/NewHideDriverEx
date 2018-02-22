#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "HideDiver.h"

#define IOCTL_BASE  0x800
#define MY_CTL_CODE(i) CTL_CODE(FILE_DEVICE_NULL, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HELLO MY_CTL_CODE(0)  

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

NTSYSAPI
NTSTATUS
NTAPI
IoCreateDriver(
    IN PUNICODE_STRING DriverName    OPTIONAL,
    IN PDRIVER_INITIALIZE InitializationFunction
);

NTSYSAPI
VOID
NTAPI
IoDeleteDriver(
    IN PDRIVER_OBJECT DriverObject
);

extern PSHORT NtBuildNumber;

