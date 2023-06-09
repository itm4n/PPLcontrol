#include "common.h"
#include "OffsetFinder.h"
#include "RTCore.h"
#include "Utils.h"
#include "Controller.h"
#include <shellapi.h>

#define PPLCONTROL_STR_CMD_LIST         L"list"
#define PPLCONTROL_STR_CMD_GET          L"get"
#define PPLCONTROL_STR_CMD_SET          L"set"
#define PPLCONTROL_STR_CMD_PROTECT      L"protect"
#define PPLCONTROL_STR_CMD_UNPROTECT    L"unprotect"

VOID PrintUsage(LPWSTR Prog);
VOID PrintKernelDriverUsage();

int wmain(int argc, wchar_t* argv[])
{
    OffsetFinder* of;
    RTCore* rtc;
    Controller* ctrl;
    DWORD dwPid;

    LPWSTR* szArglist;
    int nArgs;
        
    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (NULL == szArglist)
    {
        ERROR(L"Failed to parse command line.");
        return 1;
    }

    if (nArgs < 2)
    {
        PrintUsage(szArglist[0]);
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

    if (!_wcsicmp(szArglist[1], PPLCONTROL_STR_CMD_LIST))
    {
        if (!ctrl->ListProtectedProcesses())
            return 2;
    }
    else if (!_wcsicmp(szArglist[1], PPLCONTROL_STR_CMD_GET) || !_wcsicmp(szArglist[1], PPLCONTROL_STR_CMD_UNPROTECT))
    {
        ++szArglist;
        --nArgs;

        if (nArgs < 2)
        {
            ERROR(L"Missing argument(s) for command: %ws", szArglist[0]);
            return 1;
        }

        if (!(dwPid = wcstoul(szArglist[1], nullptr, 10)))
        {
            ERROR(L"Failed to parse argument as an unsigned integer: %ws", szArglist[1]);
            return 1;
        }

        if (!_wcsicmp(szArglist[0], PPLCONTROL_STR_CMD_GET))
        {
            if (!ctrl->GetProcessProtection(dwPid))
                return 2;
        }
        else if (!_wcsicmp(szArglist[0], PPLCONTROL_STR_CMD_UNPROTECT))
        {
            if (!ctrl->UnprotectProcess(dwPid))
                return 2;
        }
        else
        {
            ERROR(L"Unknown command: %ws", szArglist[0]);
            return 1;
        }
    }
    else if (!_wcsicmp(szArglist[1], PPLCONTROL_STR_CMD_SET) || !_wcsicmp(szArglist[1], PPLCONTROL_STR_CMD_PROTECT))
    {
        ++szArglist;
        --nArgs;

        if (nArgs < 4)
        {
            ERROR(L"Missing argument(s) for command: %ws", szArglist[0]);
            return 1;
        }

        if (!(dwPid = wcstoul(szArglist[1], nullptr, 10)))
        {
            ERROR(L"Failed to parse argument as an unsigned integer: %ws", szArglist[1]);
            return 1;
        }

        if (!_wcsicmp(szArglist[0], PPLCONTROL_STR_CMD_SET))
        {
            if (!ctrl->SetProcessProtection(dwPid, szArglist[2], szArglist[3]))
                return 2;
        }
        else if (!_wcsicmp(szArglist[0], PPLCONTROL_STR_CMD_PROTECT))
        {
            if (!ctrl->ProtectProcess(dwPid, szArglist[2], szArglist[3]))
                return 2;
        }
        else
        {
            ERROR(L"Unknown command: %ws", szArglist[0]);
            return 1;
        }
    }
    else
    {
        ERROR(L"Unknown command: %ws", szArglist[1]);
        return 1;
    }

    // Free memory allocated for CommandLineToArgvW arguments.
    LocalFree(szArglist);

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
