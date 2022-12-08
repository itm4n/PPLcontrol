#pragma once

#include "common.h"

#define UTILS_STR_PROTECTION_LEVEL_NONE				L"None"
#define UTILS_STR_PROTECTION_LEVEL_PP				L"PP"
#define UTILS_STR_PROTECTION_LEVEL_PPL				L"PPL"
#define UTILS_STR_SIGNER_TYPE_NONE					L"None"

#define UTILS_STR_SIGNER_TYPE_AUTHENTICODE			L"Authenticode"
#define UTILS_STR_SIGNER_TYPE_CODEGEN				L"CodeGen"
#define UTILS_STR_SIGNER_TYPE_ANTIMALWARE			L"Antimalware"
#define UTILS_STR_SIGNER_TYPE_LSA					L"Lsa"
#define UTILS_STR_SIGNER_TYPE_WINDOWS				L"Windows"
#define UTILS_STR_SIGNER_TYPE_WINTCB				L"WinTcb"
#define UTILS_STR_SIGNER_TYPE_WINSYSTEM				L"WinSystem"
#define UTILS_STR_SIGNER_TYPE_APP					L"App"

// The following signing levels are defined in winnt.h (see type SE_SIGNING_LEVEL)
#define UTILS_STR_SE_SIGNING_LEVEL_UNCHECKED		L"Unchecked"		// 0x00000000
#define UTILS_STR_SE_SIGNING_LEVEL_UNSIGNED			L"Unsigned"			// 0x00000001
#define UTILS_STR_SE_SIGNING_LEVEL_ENTERPRISE		L"Enterprise"		// 0x00000002
#define UTILS_STR_SE_SIGNING_LEVEL_DEVELOPER		L"Developer"		// 0x00000003 (Custom1)
#define UTILS_STR_SE_SIGNING_LEVEL_AUTHENTICODE		L"Authenticode"		// 0x00000004
#define UTILS_STR_SE_SIGNING_LEVEL_CUSTOM_2			L"Custom2"			// 0x00000005
#define UTILS_STR_SE_SIGNING_LEVEL_STORE			L"Store"			// 0x00000006
#define UTILS_STR_SE_SIGNING_LEVEL_ANTIMALWARE		L"Antimalware"		// 0x00000007 (Custom3)
#define UTILS_STR_SE_SIGNING_LEVEL_MICROSOFT		L"Microsoft"		// 0x00000008
#define UTILS_STR_SE_SIGNING_LEVEL_CUSTOM_4			L"Custom4"			// 0x00000009
#define UTILS_STR_SE_SIGNING_LEVEL_CUSTOM_5			L"Custom5"			// 0x0000000A
#define UTILS_STR_SE_SIGNING_LEVEL_DYNAMIC_CODEGEN	L"DynamicCodegen"	// 0x0000000B
#define UTILS_STR_SE_SIGNING_LEVEL_WINDOWS			L"Windows"			// 0x0000000C
#define UTILS_STR_SE_SIGNING_LEVEL_CUSTOM_7			L"Custom7"			// 0x0000000D
#define UTILS_STR_SE_SIGNING_LEVEL_WINDOWS_TCB		L"WindowsTcb"		// 0x0000000E
#define UTILS_STR_SE_SIGNING_LEVEL_CUSTOM_6			L"Custom6"			// 0x0000000F

#define CASE_STR( c ) case c: return UTILS_STR_##c

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