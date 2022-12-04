#pragma once

#include "common.h"

#define RTC64_DEVICE_NAME_W L"RTCore64"
#define RTC32_DEVICE_NAME_W L"RTCore32"

// https://github.com/RedCursorSecurityConsulting/PPLKiller/blob/master/main.cpp
#define RTC64_IOCTL_MEMORY_READ 0x80002048
#define RTC64_IOCTL_MEMORY_WRITE 0x8000204c

// https://github.com/RedCursorSecurityConsulting/PPLKiller/blob/master/main.cpp
struct RTC64_MSR_READ {
	DWORD Register;
	DWORD ValueHigh;
	DWORD ValueLow;
};

// https://github.com/RedCursorSecurityConsulting/PPLKiller/blob/master/main.cpp
struct RTC64_MEMORY_READ {
	BYTE Pad0[8];
	DWORD64 Address;
	BYTE Pad1[8];
	DWORD Size;
	DWORD Value;
	BYTE Pad3[16];
};

// https://github.com/RedCursorSecurityConsulting/PPLKiller/blob/master/main.cpp
struct RTC64_MEMORY_WRITE {
	BYTE Pad0[8];
	DWORD64 Address;
	BYTE Pad1[8];
	DWORD Size;
	DWORD Value;
	BYTE Pad3[16];
};

#ifdef _WIN64
#define RTC_DEVICE_NAME_W RTC64_DEVICE_NAME_W
#else
#define RTC_DEVICE_NAME_W RTC32_DEVICE_NAME_W
#endif

#ifdef _WIN64
#define RTC_MSR_READ RTC64_MSR_READ
#define RTC_MEMORY_READ RTC64_MEMORY_READ
#define RTC_MEMORY_WRITE RTC64_MEMORY_WRITE
#else
#error RTCore driver 32-bit structures not defined
#endif

#ifdef _WIN64
#define RTC_IOCTL_MEMORY_READ RTC64_IOCTL_MEMORY_READ
#define RTC_IOCTL_MEMORY_WRITE RTC64_IOCTL_MEMORY_WRITE
#else
#error RTCore driver IOCTLs not defined
#endif

class RTCore
{
public:
	RTCore();
	~RTCore();
	BOOL Read8(ULONG_PTR Address, PBYTE Value);
	BOOL Read16(ULONG_PTR Address, PWORD Value);
	BOOL Read32(ULONG_PTR Address, PDWORD Value);
	BOOL Read64(ULONG_PTR Address, PDWORD64 Value);
	BOOL ReadPtr(ULONG_PTR Address, PULONG_PTR Value);
	BOOL Write8(ULONG_PTR Address, BYTE Value);
	BOOL Write16(ULONG_PTR Address, WORD Value);
	BOOL Write32(ULONG_PTR Address, DWORD Value);
	BOOL Write64(ULONG_PTR Address, DWORD64 Value);

private:
	LPWSTR _DeviceName;
	HANDLE _DeviceHandle;

private:
	BOOL Initialize();
	BOOL Read(ULONG_PTR Address, DWORD ValueSize, PDWORD Value);
	BOOL Write(ULONG_PTR Address, DWORD ValueSize, DWORD Value);
};