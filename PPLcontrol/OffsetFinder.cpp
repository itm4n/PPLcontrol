#include "OffsetFinder.h"
#include "RTCore.h"
#include "Utils.h"

OffsetFinder::OffsetFinder()
{
	_KernelModule = LoadLibraryW(OF_STR_KERNEL_IMAGE_FILE_NAME_W);
}

OffsetFinder::~OffsetFinder()
{
	if (_KernelModule)
		FreeLibrary(_KernelModule);
}

DWORD OffsetFinder::GetOffset(Offset Name)
{
	return _OffsetMap[Name];
}

BOOL OffsetFinder::FindAllOffsets()
{
	if (!FindKernelPsInitialSystemProcessOffset())
		return FALSE;

	if (!FindProcessUniqueProcessIdOffset())
		return FALSE;

	if (!FindProcessProtectionOffset())
		return FALSE;

	if (!FindProcessActiveProcessLinksOffset())
		return FALSE;

	if (!FindProcessSignatureLevelOffset())
		return FALSE;

	if (!FindProcessSectionSignatureLevelOffset())
		return FALSE;

	return TRUE;
}

BOOL OffsetFinder::FindKernelPsInitialSystemProcessOffset()
{
	ULONG_PTR pPsInitialSystemProcess;
	DWORD dwPsInitialSystemProcessOffset;

	if (_OffsetMap.find(Offset::KernelPsInitialSystemProcess) != _OffsetMap.end())
		return TRUE;

	if (!(pPsInitialSystemProcess = (ULONG_PTR)GetProcAddress(_KernelModule, OF_STR_PSINITIALSYSTEMPROCESS_SYMBOL_NAME_A)))
	{
		ERROR(L"The procedure '%ws' was not found.", OF_STR_PSINITIALSYSTEMPROCESS_SYMBOL_NAME_W);
		return FALSE;
	}

	DEBUG(L"%ws @ 0x%016llx", OF_STR_PSINITIALSYSTEMPROCESS_SYMBOL_NAME_W, (DWORD64)pPsInitialSystemProcess);

	dwPsInitialSystemProcessOffset = (DWORD)(pPsInitialSystemProcess - (ULONG_PTR)_KernelModule);

	DEBUG(L"Offset: 0x%08x", dwPsInitialSystemProcessOffset);

	_OffsetMap.insert(std::make_pair(Offset::KernelPsInitialSystemProcess, dwPsInitialSystemProcessOffset));

	return TRUE;
}

BOOL OffsetFinder::FindProcessActiveProcessLinksOffset()
{
	WORD wActiveProcessLinks;

	if (_OffsetMap.find(Offset::ProcessActiveProcessLinks) != _OffsetMap.end())
		return TRUE;
	
	if (_OffsetMap.find(Offset::ProcessUniqueProcessId) == _OffsetMap.end())
	{
		ERROR(L"The offset 'UniqueProcessId' is not defined.");
		return FALSE;
	}

	wActiveProcessLinks = (WORD)_OffsetMap[Offset::ProcessUniqueProcessId] + sizeof(HANDLE);

	DEBUG(L"Offset: 0x%04x", wActiveProcessLinks);

	_OffsetMap.insert(std::make_pair(Offset::ProcessActiveProcessLinks, wActiveProcessLinks));

	return TRUE;
}

BOOL OffsetFinder::FindProcessUniqueProcessIdOffset()
{
	FARPROC pPsGetProcessId;
	WORD wUniqueProcessIdOffset;

	if (_OffsetMap.find(Offset::ProcessUniqueProcessId) != _OffsetMap.end())
		return TRUE;

	if (!(pPsGetProcessId = GetProcAddress(_KernelModule, OF_STR_PSGETPROCESSID_PROC_NAME_A)))
	{
		ERROR(L"The procedure '%ws' was not found", OF_STR_PSGETPROCESSID_PROC_NAME_W);
		return FALSE;
	}

	DEBUG(L"%ws @ 0x%016llx", OF_STR_PSGETPROCESSID_PROC_NAME_W, (DWORD64)pPsGetProcessId);

#ifdef _WIN64
	memcpy_s(&wUniqueProcessIdOffset, sizeof(wUniqueProcessIdOffset), (PVOID)((ULONG_PTR)pPsGetProcessId + 3), sizeof(wUniqueProcessIdOffset));
#else
	memcpy_s(&wUniqueProcessIdOffset, sizeof(wUniqueProcessIdOffset), (PVOID)((ULONG_PTR)pPsGetProcessId + 2), sizeof(wUniqueProcessIdOffset));
#endif

	DEBUG(L"Offset: 0x%04x", wUniqueProcessIdOffset);

	if (wUniqueProcessIdOffset > 0x0fff)
	{
		ERROR(L"The offset value of 'UniqueProcessId' is greater than the maximum allowed (0x%04x).", wUniqueProcessIdOffset);
		return FALSE;
	}

	_OffsetMap.insert(std::make_pair(Offset::ProcessUniqueProcessId, wUniqueProcessIdOffset));

	return TRUE;
}

BOOL OffsetFinder::FindProcessProtectionOffset()
{
	FARPROC pPsIsProtectedProcess, pPsIsProtectedProcessLight;
	WORD wProtectionOffsetA, wProtectionOffsetB;

	if (_OffsetMap.find(Offset::ProcessProtection) != _OffsetMap.end())
		return TRUE;

	if (!(pPsIsProtectedProcess = GetProcAddress(_KernelModule, OF_STR_PSISPROTECTEDPROCESS_PROC_NAME_A)))
	{
		ERROR(L"The procedure '%ws' was not found", OF_STR_PSISPROTECTEDPROCESS_PROC_NAME_W);
		return FALSE;
	}

	DEBUG(L"%ws @ 0x%016llx", OF_STR_PSISPROTECTEDPROCESS_PROC_NAME_W, (DWORD64)pPsIsProtectedProcess);

	if (!(pPsIsProtectedProcessLight = GetProcAddress(_KernelModule, OF_STR_PSISPROTECTEDPROCESSLIGHT_PROC_NAME_A)))
	{
		ERROR(L"The procedure '%ws' was not found", OF_STR_PSISPROTECTEDPROCESSLIGHT_PROC_NAME_W);
		return FALSE;
	}

	DEBUG(L"%ws @ 0x%016llx", OF_STR_PSISPROTECTEDPROCESSLIGHT_PROC_NAME_W, (DWORD64)pPsIsProtectedProcessLight);

	memcpy_s(&wProtectionOffsetA, sizeof(wProtectionOffsetA), (PVOID)((ULONG_PTR)pPsIsProtectedProcess + 2), sizeof(wProtectionOffsetA));
	memcpy_s(&wProtectionOffsetB, sizeof(wProtectionOffsetB), (PVOID)((ULONG_PTR)pPsIsProtectedProcessLight + 2), sizeof(wProtectionOffsetB));

	DEBUG(L"Offset in %ws: 0x%04x | Offset in %ws: 0x%04x", OF_STR_PSISPROTECTEDPROCESS_PROC_NAME_W, wProtectionOffsetA, OF_STR_PSISPROTECTEDPROCESSLIGHT_PROC_NAME_W, wProtectionOffsetB);

	if (wProtectionOffsetA != wProtectionOffsetB || wProtectionOffsetA > 0x0fff)
	{
		ERROR(L"The offset value of 'Protection' is inconsistent or is greater than the maximum allowed (0x%04x / 0x%04x)", wProtectionOffsetA, wProtectionOffsetB);
		return FALSE;
	}

	_OffsetMap.insert(std::make_pair(Offset::ProcessProtection, wProtectionOffsetA));

	return TRUE;
}

BOOL OffsetFinder::FindProcessSignatureLevelOffset()
{
	WORD wSignatureLevel;

	if (_OffsetMap.find(Offset::ProcessSignatureLevel) != _OffsetMap.end())
		return TRUE;

	if (_OffsetMap.find(Offset::ProcessProtection) == _OffsetMap.end())
	{
		ERROR(L"The offset 'Protection' is not defined.");
		return FALSE;
	}

	wSignatureLevel = (WORD)_OffsetMap[Offset::ProcessProtection] - (2 * sizeof(UCHAR));

	DEBUG(L"Offset: 0x%04x", wSignatureLevel);

	_OffsetMap.insert(std::make_pair(Offset::ProcessSignatureLevel, wSignatureLevel));

	return TRUE;
}

BOOL OffsetFinder::FindProcessSectionSignatureLevelOffset()
{
	WORD wSectionSignatureLevel;

	if (_OffsetMap.find(Offset::ProcessSectionSignatureLevel) != _OffsetMap.end())
		return TRUE;

	if (_OffsetMap.find(Offset::ProcessProtection) == _OffsetMap.end())
	{
		ERROR(L"The offset 'Protection' is not defined.");
		return FALSE;
	}

	wSectionSignatureLevel = (WORD)_OffsetMap[Offset::ProcessProtection] - sizeof(UCHAR);

	DEBUG(L"Offset: 0x%04x", wSectionSignatureLevel);

	_OffsetMap.insert(std::make_pair(Offset::ProcessSectionSignatureLevel, wSectionSignatureLevel));

	return TRUE;
}