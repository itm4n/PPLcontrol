#pragma once

#include <Windows.h>
#include <iostream>

#define PPL_CONTROL_DEBUG_ENABLED FALSE

#define WIDEH(x) L##x
#define WIDE(x) WIDEH(x)
#define NOOP do {} while(0)

#if PPL_CONTROL_DEBUG_ENABLED == TRUE
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