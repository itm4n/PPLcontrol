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
        return (UCHAR)SignatureLevel::Unchecked;
    case PsProtectedSignerAuthenticode:
        return (UCHAR)SignatureLevel::Authenticode;
    case PsProtectedSignerCodeGen:
        return (UCHAR)SignatureLevel::DynamicCodegen;
    case PsProtectedSignerAntimalware:
        return (UCHAR)SignatureLevel::Antimalware;
    case PsProtectedSignerLsa:
        return (UCHAR)SignatureLevel::Windows;
    case PsProtectedSignerWindows:
        return (UCHAR)SignatureLevel::Windows;
    case PsProtectedSignerWinTcb:
        return (UCHAR)SignatureLevel::WindowsTcb;
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
        return (UCHAR)SignatureLevel::Unchecked;
    case PsProtectedSignerAuthenticode:
        return (UCHAR)SignatureLevel::Authenticode;
    case PsProtectedSignerCodeGen:
        return (UCHAR)SignatureLevel::Store;
    case PsProtectedSignerAntimalware:
        return (UCHAR)SignatureLevel::Antimalware;
    case PsProtectedSignerLsa:
        return (UCHAR)SignatureLevel::Microsoft;
    case PsProtectedSignerWindows:
        return (UCHAR)SignatureLevel::Windows;
    //case PsProtectedSignerWinTcb:
    //    return (UCHAR)SignatureLevel::WindowsTcb;
    case PsProtectedSignerWinTcb:
        return (UCHAR)SignatureLevel::Windows; // Section signature level is actually 'Windows' in this case.
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
    case (UCHAR)SignatureLevel::Unchecked:
        return UTILS_STR_SIGNATURE_LEVEL_UNCHECKED;
    case (UCHAR)SignatureLevel::Unsigned:
        return UTILS_STR_SIGNATURE_LEVEL_UNSIGNED;
    case (UCHAR)SignatureLevel::Enterprise:
        return UTILS_STR_SIGNATURE_LEVEL_ENTERPRISE;
    case (UCHAR)SignatureLevel::Custom1:
        return UTILS_STR_SIGNATURE_LEVEL_CUSTOM1;
    case (UCHAR)SignatureLevel::Authenticode:
        return UTILS_STR_SIGNATURE_LEVEL_AUTHENTICODE;
    case (UCHAR)SignatureLevel::Custom2:
        return UTILS_STR_SIGNATURE_LEVEL_CUSTOM2;
    case (UCHAR)SignatureLevel::Store:
        return UTILS_STR_SIGNATURE_LEVEL_STORE;
    case (UCHAR)SignatureLevel::Antimalware:
        return UTILS_STR_SIGNATURE_LEVEL_ANTIMALWARE;
    case (UCHAR)SignatureLevel::Microsoft:
        return UTILS_STR_SIGNATURE_LEVEL_MICROSOFT;
    case (UCHAR)SignatureLevel::Custom4:
        return UTILS_STR_SIGNATURE_LEVEL_CUSTOM4;
    case (UCHAR)SignatureLevel::Custom5:
        return UTILS_STR_SIGNATURE_LEVEL_CUSTOM5;
    case (UCHAR)SignatureLevel::DynamicCodegen:
        return UTILS_STR_SIGNATURE_LEVEL_DYNAMICCODEGEN;
    case (UCHAR)SignatureLevel::Windows:
        return UTILS_STR_SIGNATURE_LEVEL_WINDOWS;
    case (UCHAR)SignatureLevel::WindowsProtectedProcessLight:
        return UTILS_STR_SIGNATURE_LEVEL_WINDOWSPROTECTEDPROCESSLIGHT;
    case (UCHAR)SignatureLevel::WindowsTcb:
        return UTILS_STR_SIGNATURE_LEVEL_WINDOWSTCB;
    case (UCHAR)SignatureLevel::Custom6:
        return UTILS_STR_SIGNATURE_LEVEL_CUSTOM6;
    }

    ERROR(L"Failed to retrieve the Signature level associated to the value 0x%02x.", SignatureLevel);

    return L"Unknown";
}