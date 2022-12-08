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

UCHAR Utils::GetProtectionLevel(UCHAR Protection)
{
    return Protection & 0x07;
}

UCHAR Utils::GetSignerType(UCHAR Protection)
{
    return (Protection & 0xf0) >> 4;
}

UCHAR Utils::GetProtection(UCHAR ProtectionLevel, UCHAR SignerType)
{
    return ((UCHAR)SignerType << 4) | (UCHAR)ProtectionLevel;
}

LPCWSTR Utils::GetProtectionLevelAsString(UCHAR ProtectionLevel)
{
    switch (ProtectionLevel)
    {
    case PsProtectedTypeNone:
        return UTILS_STR_PROTECTION_LEVEL_NONE;
    case PsProtectedTypeProtectedLight:
        return UTILS_STR_PROTECTION_LEVEL_PPL;
    case PsProtectedTypeProtected:
        return UTILS_STR_PROTECTION_LEVEL_PP;
    }

    ERROR(L"Failed to retrieve the Protection level associated to the value %d.", ProtectionLevel);

    return L"Unknown";
}

LPCWSTR Utils::GetSignerTypeAsString(UCHAR SignerType)
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
    }

    ERROR(L"Failed to retrieve the Signer type associated to the value %d.", SignerType);

    return L"Unknown";
}

UCHAR Utils::GetProtectionLevelFromString(LPCWSTR ProtectionLevel)
{
    if (ProtectionLevel)
    {
        if (!_wcsicmp(ProtectionLevel, UTILS_STR_PROTECTION_LEVEL_PP))
            return PsProtectedTypeProtected;
        else if (!_wcsicmp(ProtectionLevel, UTILS_STR_PROTECTION_LEVEL_PPL))
            return PsProtectedTypeProtectedLight;
    }

    ERROR(L"Failed to retrieve the value of the Protection level '%ws'.", ProtectionLevel);

    return 0;
}

UCHAR Utils::GetSignerTypeFromString(LPCWSTR SignerType)
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

    ERROR(L"Failed to retrieve the value of the Signer type '%ws'.", SignerType);

    return 0;
}

UCHAR Utils::GetSignatureLevel(UCHAR SignerType)
{
    // https://www.alex-ionescu.com/?p=146
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return SE_SIGNING_LEVEL_UNCHECKED;
    case PsProtectedSignerAuthenticode:
        return SE_SIGNING_LEVEL_AUTHENTICODE;
    case PsProtectedSignerCodeGen:
        return SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
    case PsProtectedSignerAntimalware:
        return SE_SIGNING_LEVEL_ANTIMALWARE;
    case PsProtectedSignerLsa:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWindows:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWinTcb:
        return SE_SIGNING_LEVEL_WINDOWS_TCB;
    }

    ERROR(L"Failed to retrieve the Signature level associated to the Signer type value %d.", SignerType);

    return 0xff;
}

UCHAR Utils::GetSectionSignatureLevel(UCHAR SignerType)
{
    // https://www.alex-ionescu.com/?p=146
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return SE_SIGNING_LEVEL_UNCHECKED;
    case PsProtectedSignerAuthenticode:
        return SE_SIGNING_LEVEL_AUTHENTICODE;
    case PsProtectedSignerCodeGen:
        return SE_SIGNING_LEVEL_STORE;
    case PsProtectedSignerAntimalware:
        return SE_SIGNING_LEVEL_ANTIMALWARE;
    case PsProtectedSignerLsa:
        return SE_SIGNING_LEVEL_MICROSOFT;
    case PsProtectedSignerWindows:
        return SE_SIGNING_LEVEL_WINDOWS;
    //case PsProtectedSignerWinTcb:
    //    return SE_SIGNING_LEVEL_WINDOWS_TCB;
    case PsProtectedSignerWinTcb:
        return SE_SIGNING_LEVEL_WINDOWS; // Section signature level is actually 'Windows' in this case.
    }

    ERROR(L"Failed to retrieve the Section signature level associated to the Signer type value %d.", SignerType);

    return 0xff;
}

LPCWSTR Utils::GetSignatureLevelAsString(UCHAR SignatureLevel)
{
    UCHAR bSignatureLevel;

    bSignatureLevel = SignatureLevel & 0x0f; // Remove additional flags

    switch (bSignatureLevel)
    {
        CASE_STR(SE_SIGNING_LEVEL_UNCHECKED);
        CASE_STR(SE_SIGNING_LEVEL_UNSIGNED);
        CASE_STR(SE_SIGNING_LEVEL_ENTERPRISE);
        CASE_STR(SE_SIGNING_LEVEL_DEVELOPER);
        CASE_STR(SE_SIGNING_LEVEL_AUTHENTICODE);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_2);
        CASE_STR(SE_SIGNING_LEVEL_STORE);
        CASE_STR(SE_SIGNING_LEVEL_ANTIMALWARE);
        CASE_STR(SE_SIGNING_LEVEL_MICROSOFT);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_4);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_5);
        CASE_STR(SE_SIGNING_LEVEL_DYNAMIC_CODEGEN);
        CASE_STR(SE_SIGNING_LEVEL_WINDOWS);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_7);
        CASE_STR(SE_SIGNING_LEVEL_WINDOWS_TCB);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_6);
    }

    ERROR(L"Failed to retrieve the Signature level associated to the value 0x%02x.", SignatureLevel);

    return L"Unknown";
}