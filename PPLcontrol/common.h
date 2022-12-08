#pragma once

#include <Windows.h>
#include <iostream>

#define PPLCONTROL_DEBUG_ENABLED FALSE

#define WIDEH(x) L##x
#define WIDE(x) WIDEH(x)
#define NOOP do {} while(0)

#if PPLCONTROL_DEBUG_ENABLED == TRUE
#define DEBUG_FORMAT( f ) "DEBUG: %ws | " f "\r\n"
#define DEBUG( format, ... ) wprintf( WIDE(DEBUG_FORMAT(format)), WIDE(__FUNCTION__), __VA_ARGS__ )
#else
#define DEBUG( format, ... ) NOOP
#endif

#ifdef ERROR
#undef ERROR
#endif
#define ERROR_FORMAT( f ) "[-] " f "\r\n"
#define ERROR( format, ... ) wprintf( WIDE(ERROR_FORMAT(format)), __VA_ARGS__ )

#define LASTERROR_FORMAT( f ) "[-] The function '" f "' failed with the error code 0x%08x.\r\n"
#define LASTERROR( f ) wprintf( WIDE( LASTERROR_FORMAT(f)), GetLastError() )

#define INFO_FORMAT( f ) "[*] " f "\r\n"
#define INFO( format, ... ) wprintf( WIDE(INFO_FORMAT(format)), __VA_ARGS__ )

#define SUCCESS_FORMAT( f ) "[+] " f "\r\n"
#define SUCCESS( format, ... ) wprintf( WIDE(SUCCESS_FORMAT(format)), __VA_ARGS__ )

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