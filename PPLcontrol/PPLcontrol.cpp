#include <iostream>
#include "OffsetFinder.h"
#include "RTCore.h"
#include "Utils.h"
#include "Controller.h"

#define PPLCONTROL_STR_CMD_LIST L"list"
#define PPLCONTROL_STR_CMD_GET L"get"
#define PPLCONTROL_STR_CMD_SET L"set"
#define PPLCONTROL_STR_CMD_PROTECT L"protect"
#define PPLCONTROL_STR_CMD_UNPROTECT L"unprotect"

VOID PrintUsage(LPWSTR Prog);
VOID PrintKernelDriverUsage();

int wmain(int argc, wchar_t* argv[])
{
    OffsetFinder* of;
    RTCore* rtc;
    Controller* ctrl;
    DWORD dwPid;

    if (argc < 2)
    {
        PrintUsage(argv[0]);
        PrintKernelDriverUsage();
        return 1;
    }

    of = new OffsetFinder();
    rtc = new RTCore();
    ctrl = new Controller(rtc, of);

    if (!of->FindAllOffsets())
    {
        ERROR(L"Failed to determine the required offsets.");
        return 2;
    }

    if (!_wcsicmp(argv[1], PPLCONTROL_STR_CMD_LIST))
    {
        if (!ctrl->ListProtectedProcesses())
            return 2;
    }
    else if (!_wcsicmp(argv[1], PPLCONTROL_STR_CMD_GET) || !_wcsicmp(argv[1], PPLCONTROL_STR_CMD_UNPROTECT))
    {
        ++argv;
        --argc;

        if (argc < 2)
        {
            ERROR(L"Missing argument(s) for command: %ws", argv[0]);
            return 1;
        }

        if (!(dwPid = wcstoul(argv[1], nullptr, 10)))
        {
            ERROR(L"Failed to parse argument as an unsigned integer: %ws", argv[1]);
            return 1;
        }

        if (!_wcsicmp(argv[0], PPLCONTROL_STR_CMD_GET))
        {
            if (!ctrl->GetProcessProtection(dwPid))
                return 2;
        }
        else if (!_wcsicmp(argv[0], PPLCONTROL_STR_CMD_UNPROTECT))
        {
            if (!ctrl->UnprotectProcess(dwPid))
                return 2;
        }
        else
        {
            ERROR(L"Unknown command: %ws", argv[0]);
            return 1;
        }
    }
    else if (!_wcsicmp(argv[1], PPLCONTROL_STR_CMD_SET) || !_wcsicmp(argv[1], PPLCONTROL_STR_CMD_PROTECT))
    {
        ++argv;
        --argc;

        if (argc < 4)
        {
            ERROR(L"Missing argument(s) for command: %ws", argv[0]);
            return 1;
        }

        if (!(dwPid = wcstoul(argv[1], nullptr, 10)))
        {
            ERROR(L"Failed to parse argument as an unsigned integer: %ws", argv[1]);
            return 1;
        }

        if (!_wcsicmp(argv[0], PPLCONTROL_STR_CMD_SET))
        {
            if (!ctrl->SetProcessProtection(dwPid, argv[2], argv[3]))
                return 2;
        }
        else if (!_wcsicmp(argv[0], PPLCONTROL_STR_CMD_PROTECT))
        {
            if (!ctrl->ProtectProcess(dwPid, argv[2], argv[3]))
                return 2;
        }
        else
        {
            ERROR(L"Unknown command: %ws", argv[0]);
            return 1;
        }
    }
    else
    {
        ERROR(L"Unknown command: %ws", argv[1]);
        return 1;
    }

    DEBUG(L"Done");

    return 0;
}

VOID PrintUsage(LPWSTR Prog)
{
    wprintf(
        L"Usage:\n"
         "  %ws <CMD> <ARGS>\n"
         "\n"
         "Commands:\n"
         "  %ws\n"
         "  %ws <PID>\n"
         "  %ws <PID> <PP|PPL> <TYPE>\n"
         "  %ws <PID> <PP|PPL> <TYPE>\n"
         "  %ws <PID>\n"
         "\n"
         "Signer Types:\n"
         "  Authenticode, CodeGen, Antimalware, Lsa, Windows, WinTcb, WinSystem\n"
         "\n",
        Prog,
        PPLCONTROL_STR_CMD_LIST,
        PPLCONTROL_STR_CMD_GET,
        PPLCONTROL_STR_CMD_SET,
        PPLCONTROL_STR_CMD_PROTECT,
        PPLCONTROL_STR_CMD_UNPROTECT
    );
}

VOID PrintKernelDriverUsage()
{
    wprintf(
       L"Install the driver:\n"
        "  sc.exe create RTCore64 type= kernel start= auto binPath= C:\\PATH\\TO\\RTCore64.sys DisplayName= \"Micro - Star MSI Afterburner\"\n"
        "  net start RTCore64\n"
        "\n"
        "Uninstall the driver:\n"
        "  net stop RTCore64\n"
        "  sc.exe delete RTCore64\n"
        "\n"
    );
}