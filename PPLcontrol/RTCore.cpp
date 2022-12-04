#include "RTCore.h"

RTCore::RTCore()
{
	_DeviceName = NULL;
	_DeviceHandle = NULL;
}

RTCore::~RTCore()
{
	if (_DeviceName)
		HeapFree(GetProcessHeap(), 0, _DeviceName);
	if (_DeviceHandle)
		CloseHandle(_DeviceHandle);
}

BOOL RTCore::Read8(ULONG_PTR Address, PBYTE Value)
{
	DWORD dwValue;

	if (!this->Read32(Address, &dwValue))
		return FALSE;

	*Value = dwValue & 0xff;

	return TRUE;
}

BOOL RTCore::Read16(ULONG_PTR Address, PWORD Value)
{
	DWORD dwValue;

	if (!this->Read32(Address, &dwValue))
		return FALSE;

	*Value = dwValue & 0xffff;

	return TRUE;
}

BOOL RTCore::Read32(ULONG_PTR Address, PDWORD Value)
{
	return this->Read(Address, sizeof(*Value), Value);
}

BOOL RTCore::Read64(ULONG_PTR Address, PDWORD64 Value)
{
	DWORD dwLow, dwHigh;

	if (!this->Read32(Address, &dwLow) || !this->Read32(Address + 4, &dwHigh))
		return FALSE;

	*Value = dwHigh;
	*Value = (*Value << 32) | dwLow;

	return TRUE;
}

BOOL RTCore::ReadPtr(ULONG_PTR Address, PULONG_PTR Value)
{
#ifdef _WIN64
	return this->Read64(Address, Value);
#else
	return this->Read32(Address, Value);
#endif
}

BOOL RTCore::Write8(ULONG_PTR Address, BYTE Value)
{
	return this->Write(Address, sizeof(Value), Value);
}

BOOL RTCore::Write16(ULONG_PTR Address, WORD Value)
{
	return this->Write(Address, sizeof(Value), Value);
}

BOOL RTCore::Write32(ULONG_PTR Address, DWORD Value)
{
	return this->Write(Address, sizeof(Value), Value);
}

BOOL RTCore::Write64(ULONG_PTR Address, DWORD64 Value)
{
	DWORD dwLow, dwHigh;

	dwLow = Value & 0xffffffff;
	dwHigh = (Value >> 32) & 0xffffffff;

	return this->Write32(Address, dwLow) && this->Write32(Address + 4, dwHigh);
}

BOOL RTCore::Initialize()
{
	if (_DeviceHandle == NULL)
	{
		if ((_DeviceName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, (MAX_PATH + 1) * sizeof(WCHAR))) == NULL)
			return FALSE;

		swprintf_s(_DeviceName, MAX_PATH, L"\\\\.\\%ws", RTC_DEVICE_NAME_W);

		DEBUG(L"Device path: %ws", _DeviceName);

		if ((_DeviceHandle = CreateFileW(_DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
		{
			LASTERROR("CreateFileW");
			return FALSE;
		}

		DEBUG(L"Device handle: 0x%04x", HandleToULong(_DeviceHandle));
	}

	return TRUE;
}

BOOL RTCore::Read(ULONG_PTR Address, DWORD ValueSize, PDWORD Value)
{
	RTC_MEMORY_READ mr;

	ZeroMemory(&mr, sizeof(mr));
	mr.Address = Address;
	mr.Size = ValueSize;

	if (!this->Initialize())
		return FALSE;

	if (!DeviceIoControl(_DeviceHandle, RTC_IOCTL_MEMORY_READ, &mr, sizeof(mr), &mr, sizeof(mr), NULL, NULL))
	{
		LASTERROR("DeviceIoControl");
		return FALSE;
	}

	*Value = mr.Value;

	DEBUG(L"0x%016llx: 0x%08x", Address, *Value);

	return TRUE;
}

BOOL RTCore::Write(ULONG_PTR Address, DWORD ValueSize, DWORD Value)
{
	RTC_MEMORY_WRITE mw;

	ZeroMemory(&mw, sizeof(mw));
	mw.Address = Address;
	mw.Size = ValueSize;
	mw.Value = Value;

	if (!this->Initialize())
		return FALSE;

	if (!DeviceIoControl(_DeviceHandle, RTC_IOCTL_MEMORY_WRITE, &mw, sizeof(mw), &mw, sizeof(mw), NULL, NULL))
	{
		LASTERROR("DeviceIoControl");
		return FALSE;
	}

	return TRUE;
}