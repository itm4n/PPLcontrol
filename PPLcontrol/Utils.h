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

#define UTILS_STR_SIGNATURE_LEVEL_UNCHECKED L"Unchecked"
#define UTILS_STR_SIGNATURE_LEVEL_UNSIGNED L"Unsigned"
#define UTILS_STR_SIGNATURE_LEVEL_ENTERPRISE L"Enterprise"
#define UTILS_STR_SIGNATURE_LEVEL_CUSTOM1 L"Custom1"
#define UTILS_STR_SIGNATURE_LEVEL_AUTHENTICODE L"Authenticode"
#define UTILS_STR_SIGNATURE_LEVEL_CUSTOM2 L"Custom2"
#define UTILS_STR_SIGNATURE_LEVEL_STORE L"Store"
#define UTILS_STR_SIGNATURE_LEVEL_ANTIMALWARE L"Antimalware"
#define UTILS_STR_SIGNATURE_LEVEL_MICROSOFT L"Microsoft"
#define UTILS_STR_SIGNATURE_LEVEL_CUSTOM4 L"Custom4"
#define UTILS_STR_SIGNATURE_LEVEL_CUSTOM5 L"Custom5"
#define UTILS_STR_SIGNATURE_LEVEL_DYNAMICCODEGEN L"DynamicCodegen"
#define UTILS_STR_SIGNATURE_LEVEL_WINDOWS L"Windows"
#define UTILS_STR_SIGNATURE_LEVEL_WINDOWSPROTECTEDPROCESSLIGHT L"WindowsProtectedProcessLight"
#define UTILS_STR_SIGNATURE_LEVEL_WINDOWSTCB L"WindowsTcb"
#define UTILS_STR_SIGNATURE_LEVEL_CUSTOM6 L"Custom6"

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

enum class SignatureLevel
{
	// https://github.com/palantir/exploitguard
	Unchecked,
	Unsigned,
	Enterprise,
	Custom1,
	Authenticode,
	Custom2,
	Store,
	Antimalware,
	Microsoft,
	Custom4,
	Custom5,
	DynamicCodegen,
	Windows,
	WindowsProtectedProcessLight,
	WindowsTcb,
	Custom6
};

typedef enum _SIGNATURE_LEVEL
{

} SIGNATURE_LEVEL, * PSIGNATURE_LEVEL;

class Utils
{
public:
	static ULONG_PTR GetKernelBaseAddress();
	static ULONG_PTR GetKernelAddress(ULONG_PTR Base, DWORD Offset);
	static UCHAR GetProtectionLevel(UCHAR Protection);
	static UCHAR GetSignerType(UCHAR Protection);
	static UCHAR GetProtection(UCHAR ProtectionLevel, UCHAR SignerType);
	static LPCWSTR GetProtectionLevelAsString(UCHAR ProtectionLevel);
	static LPCWSTR GetSignerTypeAsString(UCHAR SignerType);
	static UCHAR GetProtectionLevelFromString(LPCWSTR ProtectionLevel);
	static UCHAR GetSignerTypeFromString(LPCWSTR SignerType);
    static UCHAR GetSignatureLevel(UCHAR SignerType);
    static UCHAR GetSectionSignatureLevel(UCHAR SignerType);
	static LPCWSTR GetSignatureLevelAsString(UCHAR SignatureLevel);
};