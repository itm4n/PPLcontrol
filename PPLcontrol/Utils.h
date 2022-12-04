#pragma once

#include "common.h"

#define UTILS_STR_PROTECTION_LEVEL_NONE L"None"
#define UTILS_STR_PROTECTION_LEVEL_PP L"PP"
#define UTILS_STR_PROTECTION_LEVEL_PPL L"PPL"
#define UTILS_STR_SIGNER_TYPE_NONE L"None"

#define UTILS_STR_SIGNER_TYPE_AUTHENTICODE L"Authenticode"
#define UTILS_STR_SIGNER_TYPE_CODEGEN L"CodeGen"
#define UTILS_STR_SIGNER_TYPE_ANTIMALWARE L"Antimalware"
#define UTILS_STR_SIGNER_TYPE_LSA L"Lsa"
#define UTILS_STR_SIGNER_TYPE_WINDOWS L"Windows"
#define UTILS_STR_SIGNER_TYPE_WINTCB L"WinTcb"
#define UTILS_STR_SIGNER_TYPE_WINSYSTEM L"WinSystem"
#define UTILS_STR_SIGNER_TYPE_APP L"App"

typedef enum _PS_PROTECTED_TYPE
{
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
    PsProtectedSignerNone = 0,      // 0
    PsProtectedSignerAuthenticode,  // 1
    PsProtectedSignerCodeGen,       // 2
    PsProtectedSignerAntimalware,   // 3
    PsProtectedSignerLsa,           // 4
    PsProtectedSignerWindows,       // 5
    PsProtectedSignerWinTcb,        // 6
    PsProtectedSignerWinSystem,     // 7
    PsProtectedSignerApp,           // 8
    PsProtectedSignerMax            // 9
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

class Utils
{
public:
	static ULONG_PTR GetKernelBaseAddress();
	static ULONG_PTR GetKernelAddress(ULONG_PTR Base, DWORD Offset);
	static WORD GetProtectionLevel(UCHAR Protection);
	static WORD GetSignerType(UCHAR Protection);
	static UCHAR GetProtection(WORD ProtectionLevel, WORD SignerType);
	static LPCWSTR GetProtectionLevelAsString(WORD ProtectionLevel);
	static LPCWSTR GetSignerTypeAsString(WORD SignerType);
	static WORD GetProtectionLevelFromString(LPCWSTR ProtectionLevel);
	static WORD GetSignerTypeFromString(LPCWSTR SignerType);
};