#include "Utils.h"
#include <psapi.h>

ULONG_PTR Utils::GetKernelBaseAddress()
{
    ULONG_PTR pKernelBaseAddress = 0;
    LPVOID* lpImageBase = NULL;
    DWORD dwBytesNeeded = 0;

    if (!EnumDeviceDrivers(NULL, 0, &dwBytesNeeded))
        goto cleanup;

    if (!(lpImageBase = (LPVOID*)HeapAlloc(GetProcessHeap(), 0, dwBytesNeeded)))
        goto cleanup;

    if (!EnumDeviceDrivers(lpImageBase, dwBytesNeeded, &dwBytesNeeded))
        goto cleanup;

    pKernelBaseAddress = ((ULONG_PTR*)lpImageBase)[0];

cleanup:
    if (lpImageBase)
        HeapFree(GetProcessHeap(), 0, lpImageBase);

    return pKernelBaseAddress;
}

ULONG_PTR Utils::GetKernelAddress(ULONG_PTR Base, DWORD Offset)
{
    return Base + Offset;
}

WORD Utils::GetProtectionLevel(UCHAR Protection)
{
    return Protection & 0x07;
}

WORD Utils::GetSignerType(UCHAR Protection)
{
    return (Protection & 0xf0) >> 4;
}

UCHAR Utils::GetProtection(WORD ProtectionLevel, WORD SignerType)
{
    return ((UCHAR)SignerType << 4) | (UCHAR)ProtectionLevel;
}

LPCWSTR Utils::GetProtectionLevelAsString(WORD ProtectionLevel)
{
    switch (ProtectionLevel)
    {
    case PsProtectedTypeNone:
        return UTILS_STR_PROTECTION_LEVEL_NONE;
    case PsProtectedTypeProtectedLight:
        return UTILS_STR_PROTECTION_LEVEL_PPL;
    case PsProtectedTypeProtected:
        return UTILS_STR_PROTECTION_LEVEL_PP;
    default:
        return L"Unknown";
    }
}

LPCWSTR Utils::GetSignerTypeAsString(WORD SignerType)
{
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return UTILS_STR_SIGNER_TYPE_NONE;
    case PsProtectedSignerAuthenticode:
        return UTILS_STR_SIGNER_TYPE_AUTHENTICODE;
    case PsProtectedSignerCodeGen:
        return UTILS_STR_SIGNER_TYPE_CODEGEN;
    case PsProtectedSignerAntimalware:
        return UTILS_STR_SIGNER_TYPE_ANTIMALWARE;
    case PsProtectedSignerLsa:
        return UTILS_STR_SIGNER_TYPE_LSA;
    case PsProtectedSignerWindows:
        return UTILS_STR_SIGNER_TYPE_WINDOWS;
    case PsProtectedSignerWinTcb:
        return UTILS_STR_SIGNER_TYPE_WINTCB;
    case PsProtectedSignerWinSystem:
        return UTILS_STR_SIGNER_TYPE_WINSYSTEM;
    case PsProtectedSignerApp:
        return UTILS_STR_SIGNER_TYPE_APP;
    default:
        return L"Unknown";
    }
}

WORD Utils::GetProtectionLevelFromString(LPCWSTR ProtectionLevel)
{
    if (ProtectionLevel)
    {
        if (!_wcsicmp(ProtectionLevel, UTILS_STR_PROTECTION_LEVEL_PP))
            return PsProtectedTypeProtected;
        else if (!_wcsicmp(ProtectionLevel, UTILS_STR_PROTECTION_LEVEL_PPL))
            return PsProtectedTypeProtectedLight;
    }

    return 0;
}

WORD Utils::GetSignerTypeFromString(LPCWSTR SignerType)
{
    if (SignerType)
    {
        if (!_wcsicmp(SignerType, UTILS_STR_SIGNER_TYPE_AUTHENTICODE))
            return PsProtectedSignerAuthenticode;
        else if (!_wcsicmp(SignerType, UTILS_STR_SIGNER_TYPE_CODEGEN))
            return PsProtectedSignerCodeGen;
        else if (!_wcsicmp(SignerType, UTILS_STR_SIGNER_TYPE_ANTIMALWARE))
            return PsProtectedSignerAntimalware;
        else if (!_wcsicmp(SignerType, UTILS_STR_SIGNER_TYPE_LSA))
            return PsProtectedSignerLsa;
        else if (!_wcsicmp(SignerType, UTILS_STR_SIGNER_TYPE_WINDOWS))
            return PsProtectedSignerWindows;
        else if (!_wcsicmp(SignerType, UTILS_STR_SIGNER_TYPE_WINTCB))
            return PsProtectedSignerWinTcb;
        else if (!_wcsicmp(SignerType, UTILS_STR_SIGNER_TYPE_WINSYSTEM))
            return PsProtectedSignerWinSystem;
        else if (!_wcsicmp(SignerType, UTILS_STR_SIGNER_TYPE_APP))
            return PsProtectedSignerApp;
    }

    return 0;
}