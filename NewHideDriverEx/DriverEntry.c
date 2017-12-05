#include "HideDiver.h"
#include <ntddk.h>  

#define     DEVICE_NAME                 L"\\device\\Xenos"  
#define     LINK_NAME                   L"\\dosDevices\\Xenos"  

#define IOCTL_BASE  0x800
#define MY_CTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HELLO MY_CTL_CODE(0)  

extern PSHORT NtBuildNumber;

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT pDevice;
    UNICODE_STRING ustrDeviceName;  //设备名称  
    UNICODE_STRING ustrSymLinkName; //符号链接名  
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

VOID Reinitialize(
    _In_     PDRIVER_OBJECT        pDriverObject,
    _In_opt_ PVOID                 Context,
    _In_     ULONG                 Count
    )
{
    if (*NtBuildNumber < 8000)
        HideDriverWin7(pDriverObject);
    else
        HideDriverWin10(pDriverObject);
}

// function to dispatch the IRPs  
NTSTATUS DispatchOK(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(
    IN PDRIVER_OBJECT   pDriverObject)
{
    UNICODE_STRING strLink;
    RtlInitUnicodeString(&strLink, LINK_NAME);

    IoDeleteSymbolicLink(&strLink);
    IoDeleteDevice(pDriverObject->DeviceObject);
    DbgPrint("[NTModelDrv] Unloaded\n");
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
        DbgPrint("[NTModelDrv] Hello\n");
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

//处理应用层的write()函数  
NTSTATUS DispatchWrite(
    IN PDEVICE_OBJECT   pDevObj,
    IN PIRP pIrp)
{
    NTSTATUS    status = STATUS_SUCCESS;
    PVOID       userBuffer;
    PVOID       drvBuffer;
    ULONG       xferSize;

    //获得IRP堆栈的当前位置  
    PIO_STACK_LOCATION pIrpStack =
        IoGetCurrentIrpStackLocation(pIrp);
    //获得当前写的长度和缓冲  
    xferSize = pIrpStack->Parameters.Write.Length;
    userBuffer = pIrp->AssociatedIrp.SystemBuffer;
    drvBuffer = ExAllocatePoolWithTag(PagedPool, xferSize, 'tseT');
    if (drvBuffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        xferSize = 0;
    }
    //将当前缓冲中的数据写入  
    RtlCopyMemory(drvBuffer, userBuffer, xferSize);
    //完成IO，填写完成状态和传输的数据长度  
    ExFreePool(drvBuffer);
    drvBuffer = NULL;
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = xferSize;
    //完成IRP，不向下层传递  
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}
//处理应用层的read()函数  
NTSTATUS DispatchRead(
    IN PDEVICE_OBJECT   pDevObj,
    IN PIRP pIrp)
{
    NTSTATUS    status = STATUS_SUCCESS;
    PVOID       userBuffer;
    ULONG       xferSize;

    //获取IRP堆栈的当前位置  
    PIO_STACK_LOCATION pIrpStack =
        IoGetCurrentIrpStackLocation(pIrp);
    //获取传输的字节数和缓冲  
    xferSize = pIrpStack->Parameters.Read.Length;
    userBuffer = pIrp->AssociatedIrp.SystemBuffer;
    //从驱动中读数据  
    RtlCopyMemory(userBuffer, L"Hello, world",
        xferSize);
    //填写IRP中的完成状态，结束IRP操作，不向下层发送  
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = xferSize;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
    UNICODE_STRING  DeviceName;
    UNICODE_STRING  LinkName;
    NTSTATUS        status;
    PDEVICE_OBJECT  pDriverDeviceObject;
    PDEVICE_EXTENSION   pDevExt;
    ULONG i;

    //DbgPrint("Driver loaded.");  
    pDriverObject->DriverUnload = DriverUnload;

    // init strings  
    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&LinkName, LINK_NAME);
    
    // to communicate with usermode, we need a device  
    status = IoCreateDevice(
        pDriverObject,        // ptr to caller object  
        sizeof(DEVICE_EXTENSION),  // extension device allocated byte number  
        &DeviceName,         // device name   
        FILE_DEVICE_UNKNOWN,
        0,                   // no special caracteristics  
        FALSE,               // we can open many handles in same time  
        &pDriverDeviceObject); // [OUT] ptr to the created object  

    if (!NT_SUCCESS(status))
        return STATUS_NO_SUCH_DEVICE;

    pDriverDeviceObject->Flags |= DO_BUFFERED_IO;

    // we also need a symbolic link  
    status = IoCreateSymbolicLink(&LinkName, &DeviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(pDriverDeviceObject);
        return STATUS_NO_SUCH_DEVICE;
    }

    //pDevExt->ustrSymLinkName = LinkName;

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        pDriverObject->MajorFunction[i] = DispatchOK;

    // handle IRPs  
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    IoRegisterDriverReinitialization(pDriverObject, Reinitialize, NULL);

    return STATUS_SUCCESS;
}