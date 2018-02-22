#include "pch.h"

PDRIVER_OBJECT g_pDriverObject = NULL;

#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

// #define HOST_ADDRESS "211.149.184.238"
// #define HOST_ADDRESS "183.61.146.197"

VOID KernelSleep(LONG msec)
{
    LARGE_INTEGER my_interval;
    my_interval.QuadPart = DELAY_ONE_MILLISECOND;
    my_interval.QuadPart *= msec;
    KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

NTSTATUS DispatchIoctl(
    PDEVICE_OBJECT pDevObj,
    PIRP pIrp
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION pIrpStack;
    ULONG uIoControlCode;
    PVOID pIoBuffer;
    ULONG uInSize;
    ULONG uOutSize;

    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
    pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
    uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (uIoControlCode)
    {
    case IOCTL_HELLO:
    {
        DPRINT("DrvEnjoy Hello.\n");
        status = STATUS_SUCCESS;
    }
    break;
    }

    if (status == STATUS_SUCCESS)
        pIrp->IoStatus.Information = uOutSize;
    else
        pIrp->IoStatus.Information = 0;

    /////////////////////////////////////  
    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS DispatchOK(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DrvUnload(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING strLink;
    RtlInitUnicodeString(&strLink, L"\\DosDevices\\BLCheers");

    IoDeleteSymbolicLink(&strLink);
    IoDeleteDevice(pDriverObject->DeviceObject);
    DPRINT("DrvEnjoy Unload.\n");
}

NTSTATUS DriverInit(PDRIVER_OBJECT DriverObject, PDRIVER_DISPATCH pControl)
{
    NTSTATUS        status;
    UNICODE_STRING  SymLink, DevName;
    PDEVICE_OBJECT  devobj;
    ULONG           t;

    RtlInitUnicodeString(&DevName, L"\\Device\\BLCheers");
    status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_NULL, FILE_DEVICE_SECURE_OPEN, FALSE, &devobj);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&SymLink, L"\\DosDevices\\BLCheers");
    status = IoCreateSymbolicLink(&SymLink, &DevName);

    devobj->Flags |= DO_BUFFERED_IO;

    for (t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
        DriverObject->MajorFunction[t] = &DispatchOK;

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = pControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = &DispatchOK;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &DispatchOK;
    DriverObject->DriverUnload = DrvUnload;

    devobj->Flags &= ~DO_DEVICE_INITIALIZING;

    return status;
}

VOID
DelObject(
    _In_ PVOID StartContext
) 
{
    PULONG_PTR pZero = NULL;
    KernelSleep(5000);
    ObMakeTemporaryObject(g_pDriverObject);
    DPRINT("test seh.\n");
    __try {
        *pZero = 0x100;
    }
    __except (1)
    {
        DPRINT("seh success.\n");
    }
}

VOID Reinitialize(
    _In_     PDRIVER_OBJECT        pDriverObject,
    _In_opt_ PVOID                 Context,
    _In_     ULONG                 Count
)
{
    HANDLE hThread = NULL;
    PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, DelObject, NULL);
    if (*NtBuildNumber < 8000)
        HideDriverWin7(pDriverObject);
    else
        HideDriverWin10(pDriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegisterPath)
{
    DPRINT("DrvEnjoy.\n");
    DPRINT("0x%p\n", pDriverObject);
    DbgBreakPoint();
    DriverInit(pDriverObject, DispatchIoctl);
    g_pDriverObject = pDriverObject;
    IoRegisterDriverReinitialization(pDriverObject, Reinitialize, NULL);
    return STATUS_SUCCESS;
}