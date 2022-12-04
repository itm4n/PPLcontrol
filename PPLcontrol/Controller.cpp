#include "Controller.h"

Controller::Controller()
{
	_rtc = new RTCore();
	_of = new OffsetFinder();

	_of->FindAllOffsets();
}

Controller::Controller(RTCore* rtc, OffsetFinder* of)
{
    _rtc = rtc;
    _of = of;
}

BOOL Controller::ListProtectedProcesses()
{
    PCTRL_PROCESS_INFO pProcessInfo = NULL;
    DWORD dwIndex, dwNumberOfProtectedProceses = 0;

    if (!GetProcessList(&pProcessInfo))
        return FALSE;

    DEBUG(L"Number of entries: %d", pProcessInfo->NumberOfEntries);

    wprintf(L"\n %6ws | %-7ws | %ws\n", L"PID", L"Level", L"Signer");
    wprintf(L" -------+---------+----------------\n");

    for (dwIndex = 0; dwIndex < pProcessInfo->NumberOfEntries; dwIndex++)
    {
        if (pProcessInfo->Entries[dwIndex].ProtectionLevel > 0)
        {
            wprintf(L" %6d | %-3ws (%d) | %ws (%d)\n",
                pProcessInfo->Entries[dwIndex].Pid,
                Utils::GetProtectionLevelAsString(pProcessInfo->Entries[dwIndex].ProtectionLevel),
                pProcessInfo->Entries[dwIndex].ProtectionLevel,
                Utils::GetSignerTypeAsString(pProcessInfo->Entries[dwIndex].SignerType),
                pProcessInfo->Entries[dwIndex].SignerType
            );

            dwNumberOfProtectedProceses++;
        }
    }

    wprintf(L"\n");

    SUCCESS(L"Enumerated %d protected processes.", dwNumberOfProtectedProceses);

    HeapFree(GetProcessHeap(), 0, pProcessInfo);

    return TRUE;
}

BOOL Controller::GetProcessProtection(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;
    WORD wProtectionLevel, wSignerType;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;
        
    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection > 0)
    {
        wProtectionLevel = Utils::GetProtectionLevel(bProtection);
        wSignerType = Utils::GetSignerType(bProtection);

        SUCCESS(L"Process with PID %d is a %ws with the Signer type %ws (%d).",
            Pid,
            Utils::GetProtectionLevelAsString(wProtectionLevel),
            Utils::GetSignerTypeAsString(wSignerType),
            wSignerType
        );
    }
    else
    {
        INFO(L"Process with PID %d is not protected.", Pid);
    }

    return TRUE;
}

BOOL Controller::SetProcessProtection(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType)
{
    ULONG_PTR pProcess;
    UCHAR bProtectionOld, bProtectionNew, bProtectionEffective;
    WORD wProtectionLevel, wSignerType;

    if (!(wProtectionLevel = Utils::GetProtectionLevelFromString(ProtectionLevel)))
    {
        ERROR(L"The supplied Protection level is invalid: %ws", ProtectionLevel);
        return FALSE;
    }

    if (!(wSignerType = Utils::GetSignerTypeFromString(SignerType)))
    {
        ERROR(L"The supplied Signer type is invalid: %ws", SignerType);
        return FALSE;
    }

    bProtectionNew = Utils::GetProtection(wProtectionLevel, wSignerType);

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtection(pProcess, &bProtectionOld))
        return FALSE;

    if (bProtectionOld == bProtectionNew)
    {
        ERROR(L"The process with PID %d already has the protection %ws-%ws.",
            Pid,
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionOld)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionOld))
        );

        return FALSE;
    }

    if (!SetProcessProtection(pProcess, bProtectionNew))
    {
        ERROR(L"Failed to set Protection %ws-%ws on process with PID %d.",
            Utils::GetProtectionLevelAsString(wProtectionLevel),
            Utils::GetSignerTypeAsString(wSignerType),
            Pid
        );

        return FALSE;
    }

    if (!GetProcessProtection(pProcess, &bProtectionEffective))
        return FALSE;

    if (bProtectionNew != bProtectionEffective)
    {
        ERROR(L"Tried to set the protection %ws-%ws, but the effective protection is: %ws-%ws.",
            Utils::GetProtectionLevelAsString(wProtectionLevel),
            Utils::GetSignerTypeAsString(wSignerType),
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionEffective)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionEffective))
        );

        return FALSE;
    }

    SUCCESS(L"The Protection %ws-%ws was set on the process with PID %d, previous protection was: %ws-%ws.",
        Utils::GetProtectionLevelAsString(wProtectionLevel),
        Utils::GetSignerTypeAsString(wSignerType),
        Pid,
        Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionOld)),
        Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionOld))
    );

    return TRUE;
}

BOOL Controller::ProtectProcess(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection > 0)
    {
        ERROR(L"Process with PID %d is already protected, current protection is %ws-%ws.",
            Pid,
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtection)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtection))
        );

        return FALSE;
    }

    return SetProcessProtection(Pid, ProtectionLevel, SignerType);
}

BOOL Controller::UnprotectProcess(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection == 0)
    {
        ERROR(L"Process with PID %d is not protected, nothing to unprotect.", Pid);
        return FALSE;
    }

    if (!SetProcessProtection(pProcess, 0))
    {
        ERROR(L"Failed to set Protection level 'None' and Signer type 'None' on process with PID %d.", Pid);
        return FALSE;
    }

    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection != 0)
    {
        ERROR(L"Process with PID %d still appears to be protected.", Pid);
        return FALSE;
    }

    SUCCESS(L"The process with PID %d is no longer a PP(L).", Pid);

    return TRUE;
}

BOOL Controller::GetInitialSystemProcessAddress(PULONG_PTR Addr)
{
    ULONG_PTR pKernelBase, pPsInitialSystemProcess, pInitialSystemProcess;

    *Addr = 0;

    if (!(pKernelBase = Utils::GetKernelBaseAddress()))
        return FALSE;

    if (!(pPsInitialSystemProcess = Utils::GetKernelAddress(pKernelBase, _of->GetOffset(Offset::KernelPsInitialSystemProcess))))
        return FALSE;

    DEBUG(L"%ws @ 0x%016llx\n", OF_STR_PSINITIALSYSTEMPROCESS_SYMBOL_NAME_W, pPsInitialSystemProcess);

    if (!(_rtc->ReadPtr(pPsInitialSystemProcess, &pInitialSystemProcess)))
        return FALSE;

    DEBUG(L"System process @ 0x%016llx\n", pInitialSystemProcess);

    *Addr = pInitialSystemProcess;

    return TRUE;
}

BOOL Controller::GetProcessKernelAddress(DWORD Pid, PULONG_PTR Addr)
{
    PCTRL_PROCESS_INFO pProcessInfo = NULL;
    DWORD dwIndex;
    ULONG_PTR pProcess = 0;

    if (!GetProcessList(&pProcessInfo))
        return FALSE;

    for (dwIndex = 0; dwIndex < pProcessInfo->NumberOfEntries; dwIndex++)
    {
        if (pProcessInfo->Entries[dwIndex].Pid == Pid)
        {
            pProcess = pProcessInfo->Entries[dwIndex].KernelAddress;
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, pProcessInfo);

    if (pProcess == 0)
    {
        ERROR(L"Failed to retrieve Kernel address of process with PID %d.", Pid);
        return FALSE;
    }

    *Addr = pProcess;

    return TRUE;
}

BOOL Controller::GetProcessList(PCTRL_PROCESS_INFO *List)
{
    BOOL bResult = FALSE;
    PCTRL_PROCESS_INFO pProcessList = NULL, pProcessListNew;
    DWORD dwBaseSize = 4096, dwSize, dwNumberOfEntries = 0;
    DWORD64 dwProcessId;
    ULONG_PTR pProcess, pInitialSystemProcess;
    UCHAR bProtection;

    if (!(pProcessList = (PCTRL_PROCESS_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBaseSize)))
        return FALSE;

    dwSize = sizeof(pProcessList->NumberOfEntries);

    if (!GetInitialSystemProcessAddress(&pInitialSystemProcess))
        return FALSE;

    pProcess = pInitialSystemProcess;

    do
    {
        if (!(_rtc->Read64(pProcess + _of->GetOffset(Offset::ProcessUniqueProcessId), &dwProcessId)))
            break;

        DEBUG(L"Process @ 0x%016llx has PID %d\n", pProcess, (DWORD)dwProcessId);

        if (!GetProcessProtection(pProcess, &bProtection))
            break;

        dwSize += sizeof((*List)[0]);

        if (dwSize >= dwBaseSize)
        {
            dwBaseSize *= 2;
            if (!(pProcessListNew = (PCTRL_PROCESS_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pProcessList, dwBaseSize)))
                break;

            pProcessList = pProcessListNew;
        }

        pProcessList->Entries[dwNumberOfEntries].KernelAddress = pProcess;
        pProcessList->Entries[dwNumberOfEntries].Pid = (DWORD)dwProcessId;
        pProcessList->Entries[dwNumberOfEntries].ProtectionLevel = Utils::GetProtectionLevel(bProtection);
        pProcessList->Entries[dwNumberOfEntries].SignerType = Utils::GetSignerType(bProtection);

        dwNumberOfEntries++;

        if (!(_rtc->ReadPtr(pProcess + _of->GetOffset(Offset::ProcessActiveProcessLinks), &pProcess)))
            break;

        pProcess = pProcess - _of->GetOffset(Offset::ProcessActiveProcessLinks);

    } while (pProcess != pInitialSystemProcess);

    if (pProcess == pInitialSystemProcess)
    {
        pProcessList->NumberOfEntries = dwNumberOfEntries;
        bResult = TRUE;
        *List = pProcessList;
    }

    if (!bResult && pProcessList)
        HeapFree(GetProcessHeap(), 0, pProcessList);

    return bResult;
}

BOOL Controller::GetProcessProtection(ULONG_PTR Addr, PUCHAR Protection)
{
    UCHAR bProtection;

    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessProtection), &bProtection)))
    {
#ifdef _WIN64
        ERROR(L"Failed to retrieve Protection attribute of process with @ 0x%016llx.", Addr);
#else
        ERROR(L"Failed to retrieve Protection attribute of process with @ 0x%08x.", Addr);
#endif
        return FALSE;
    }

    *Protection = bProtection;

    return TRUE;
}

BOOL Controller::SetProcessProtection(ULONG_PTR Addr, UCHAR Protection)
{
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessProtection), Protection);
}