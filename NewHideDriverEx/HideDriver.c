#include "HideDiver.h"

#pragma warning(disable : 4047)  

typedef NTSTATUS(__fastcall *MiProcessLoaderEntry)(PVOID pDriverSection, int bLoad);

MiProcessLoaderEntry g_pfnMiProcessLoaderEntry = NULL;

PVOID GetCallPoint(PVOID pCallPoint)
{
    ULONG dwOffset = 0;
    ULONG_PTR returnAddress = 0;
    LARGE_INTEGER returnAddressTemp = { 0 };
    PUCHAR pFunAddress = NULL;

    if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))
        return NULL;

    pFunAddress = pCallPoint;
    // 函数偏移  
    RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 1), sizeof(ULONG));

    // JMP向上跳转  
    if ((dwOffset & 0x10000000) == 0x10000000)
    {
        dwOffset = dwOffset + 5 + pFunAddress;
        returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;
        returnAddressTemp.LowPart = dwOffset;
        returnAddress = returnAddressTemp.QuadPart;
        return (PVOID)returnAddress;
    }

    returnAddress = (ULONG_PTR)dwOffset + 5 + pFunAddress;
    return (PVOID)returnAddress;

}

PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName, IN PUCHAR pStartAddress, IN UCHAR* pFeatureCode, IN ULONG FeatureCodeNum, ULONG SerSize, UCHAR SegCode, ULONG AddNum, BOOLEAN ByName)
{
    ULONG dwIndex = 0;
    PUCHAR pFunAddress = NULL;
    ULONG dwCodeNum = 0;

    if (pFeatureCode == NULL)
        return NULL;

    if (FeatureCodeNum >= 15)
        return NULL;

    if (SerSize > 0x1024)
        return NULL;

    if (ByName)
    {
        if (pFunName == NULL || !MmIsAddressValid(pFunName->Buffer))
            return NULL;

        pFunAddress = (PUCHAR)MmGetSystemRoutineAddress(pFunName);
        if (pFunAddress == NULL)
            return NULL;
    }
    else
    {
        if (pStartAddress == NULL || !MmIsAddressValid(pStartAddress))
            return NULL;

        pFunAddress = pStartAddress;
    }

    for (dwIndex = 0; dwIndex < SerSize; dwIndex++)
    {
        __try
        {
            if (pFunAddress[dwIndex] == pFeatureCode[dwCodeNum] || pFeatureCode[dwCodeNum] == SegCode)
            {
                dwCodeNum++;

                if (dwCodeNum == FeatureCodeNum)
                    return pFunAddress + dwIndex - dwCodeNum + 1 + AddNum;

                continue;
            }

            dwCodeNum = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    return 0;
}

BOOLEAN HideDriverWin7(PDRIVER_OBJECT pTargetDriverObject)
{
    UNICODE_STRING usFuncName = { 0 };
    PUCHAR pMiProcessLoaderEntry = NULL;
    size_t i = 0;

    RtlInitUnicodeString(&usFuncName, L"EtwWriteString");

    pMiProcessLoaderEntry = (PUCHAR)MmGetSystemRoutineAddress(&usFuncName);

    pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x600;

    __try {
        for (i = 0; i < 0x600; i++)
        {

            if (*pMiProcessLoaderEntry == 0xbb && *(pMiProcessLoaderEntry + 1) == 0x01 && *(pMiProcessLoaderEntry + 2) == 0x0 &&
                *(pMiProcessLoaderEntry + 5) == 0x48 && *(pMiProcessLoaderEntry + 0xc) == 0x8a && *(pMiProcessLoaderEntry + 0xd) == 0xd3
                && *(pMiProcessLoaderEntry + 0xe) == 0xe8)
            {
                pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x40;
                for (i = 0; i < 0x30; i++)
                {
                    if (*pMiProcessLoaderEntry == 0x90 && *(pMiProcessLoaderEntry + 1) == 0x48)
                    {
                        pMiProcessLoaderEntry++;
                        goto MiProcessSuccess;
                    }
                    pMiProcessLoaderEntry++;
                }
                return FALSE;
            }
            pMiProcessLoaderEntry++;
        }
    }
    __except (1)
    {
        return FALSE;
    }

    return FALSE;
MiProcessSuccess:

    g_pfnMiProcessLoaderEntry = pMiProcessLoaderEntry;

    DbgPrint("0x%p\n", g_pfnMiProcessLoaderEntry);

    /*////////////////////////////////隐藏驱动/////////////////////////////////*/
    g_pfnMiProcessLoaderEntry(pTargetDriverObject->DriverSection, 0);

    pTargetDriverObject->DriverSection = NULL;
    /*/////////////////////////////////////////////////////////////////////////*/

    // 破坏驱动对象特征
    pTargetDriverObject->DriverStart = NULL;
    pTargetDriverObject->DriverSize = NULL;
    pTargetDriverObject->DriverUnload = NULL;
    pTargetDriverObject->DriverInit = NULL;
    pTargetDriverObject->DeviceObject = NULL;

    return TRUE;
}

// Test On 14393
NTSTATUS HideDriverWin10(PDRIVER_OBJECT pTargetDriverObject)
{
    UNICODE_STRING usRoutie = { 0 };
    PUCHAR pAddress = NULL;

    UCHAR code[3] =
        "\xD8\xE8";

    UCHAR code2[10] =
        "\x48\x8B\xCB\xE8\x60\x60\x60\x60\x8B";

    /*
    PAGE:000000014052ABE4 48 8B D8                                      mov     rbx, rax
    PAGE:000000014052ABE7 E8 48 17 F7 FF                                call    MiUnloadSystemImage
    */

    if (pTargetDriverObject == NULL)
        return STATUS_INVALID_PARAMETER;

    RtlInitUnicodeString(&usRoutie, L"MmUnloadSystemImage");

    pAddress = GetUndocumentFunctionAddress(&usRoutie, NULL, code, 2, 0x30, 0x90, 1, TRUE);

    if (pAddress == NULL)
    {
        DbgPrint("MiUnloadSystemImage 1 faild!\n");
        return STATUS_UNSUCCESSFUL;
    }

    pAddress = GetCallPoint(pAddress);

    if (pAddress == NULL)
    {
        DbgPrint("MiUnloadSystemImage 2 faild!\n");
        return STATUS_UNSUCCESSFUL;
    }

    /*
    PAGE:000000014049C5CF 48 8B CB                                      mov     rcx, rbx
    PAGE:000000014049C5D2 E8 31 29 C2 FF                                call    MiProcessLoaderEntry
    PAGE:000000014049C5D7 8B 05 A3 BC F0 FF                             mov     eax, cs:PerfGlobalGroupMask
    PAGE:000000014049C5DD A8 04                                         test    al, 4
    */

    pAddress = GetUndocumentFunctionAddress(NULL, pAddress, code2, 9, 0x300, 0x60, 3, FALSE);

    if (pAddress == NULL)
    {
        DbgPrint("MiProcessLoaderEntry 1 faild!\n");
        return STATUS_UNSUCCESSFUL;
    }

    g_pfnMiProcessLoaderEntry = (MiProcessLoaderEntry)GetCallPoint(pAddress);

    if (g_pfnMiProcessLoaderEntry == NULL)
    {
        DbgPrint("MiProcessLoaderEntry 2 faild!\n");
        return STATUS_UNSUCCESSFUL;
    }

    //DbgBreakPoint();

    DbgPrint("0x%p\n", g_pfnMiProcessLoaderEntry);

    /*////////////////////////////////隐藏驱动/////////////////////////////////*/
    g_pfnMiProcessLoaderEntry(pTargetDriverObject->DriverSection, 0);

    pTargetDriverObject->DriverSection = NULL;
    /*/////////////////////////////////////////////////////////////////////////*/

    // 破坏驱动对象特征
    pTargetDriverObject->DriverStart = NULL;
    pTargetDriverObject->DriverSize = NULL;
    pTargetDriverObject->DriverUnload = NULL;
    pTargetDriverObject->DriverInit = NULL;
    pTargetDriverObject->DeviceObject = NULL;

    return STATUS_SUCCESS;
}