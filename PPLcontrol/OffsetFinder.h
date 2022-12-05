#pragma once

#include "common.h"
#include <map>

#define OF_STR_KERNEL_IMAGE_FILE_NAME_W L"ntoskrnl.exe"
#define OF_STR_PSINITIALSYSTEMPROCESS_SYMBOL_NAME_A "PsInitialSystemProcess"
#define OF_STR_PSINITIALSYSTEMPROCESS_SYMBOL_NAME_W WIDE(OF_STR_PSINITIALSYSTEMPROCESS_SYMBOL_NAME_A)
#define OF_STR_PSGETPROCESSID_PROC_NAME_A "PsGetProcessId"
#define OF_STR_PSGETPROCESSID_PROC_NAME_W WIDE(OF_STR_PSGETPROCESSID_PROC_NAME_A)
#define OF_STR_PSISPROTECTEDPROCESS_PROC_NAME_A "PsIsProtectedProcess"
#define OF_STR_PSISPROTECTEDPROCESS_PROC_NAME_W WIDE(OF_STR_PSISPROTECTEDPROCESS_PROC_NAME_A)
#define OF_STR_PSISPROTECTEDPROCESSLIGHT_PROC_NAME_A "PsIsProtectedProcessLight"
#define OF_STR_PSISPROTECTEDPROCESSLIGHT_PROC_NAME_W WIDE(OF_STR_PSISPROTECTEDPROCESSLIGHT_PROC_NAME_A)

enum class Offset
{
	KernelPsInitialSystemProcess,
	ProcessActiveProcessLinks,
	ProcessUniqueProcessId,
	ProcessProtection,
	ProcessSignatureLevel,
	ProcessSectionSignatureLevel
};

class OffsetFinder
{
public:
	OffsetFinder();
	~OffsetFinder();
	DWORD GetOffset(Offset Name);
	BOOL FindAllOffsets();

private:
	HMODULE _KernelModule;
	std::map<Offset, DWORD> _OffsetMap;

private:
	BOOL FindKernelPsInitialSystemProcessOffset();
	BOOL FindProcessActiveProcessLinksOffset();
	BOOL FindProcessUniqueProcessIdOffset();
	BOOL FindProcessProtectionOffset();
	BOOL FindProcessSignatureLevelOffset();
	BOOL FindProcessSectionSignatureLevelOffset();
};