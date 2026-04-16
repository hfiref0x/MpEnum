/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2026
*
*  TITLE:       MAIN.C
*
*  VERSION:     2.00
*
*  DATE:        16 Apr 2026
*
*  Codename:    Takanami
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

typedef struct _THREAT_ENTRY {
    LIST_ENTRY ListEntry;
    MPTHREAT_INFO* MpInfo;
} THREAT_ENTRY, * PTHREAT_ENTRY;

typedef struct _CAT {
    LIST_ENTRY ListEntry;
    MPTHREAT_CATEGORY Category;
    SIZE_T NumberOfEntries;
    LIST_ENTRY ThreatEntryHead;
    WCHAR Name[MAX_PATH];
} CAT, * PCAT;

typedef struct _CAT_NAME {
    MPTHREAT_CATEGORY Category;
    LPCWSTR DisplayName;
    LPCWSTR InternalName;
} CAT_NAME, * PCAT_NAME;

typedef struct _SORTED_THREAT {
    ULONG CategoryID;
    ULONG SeverityID;
    ULONG ThreatID;
    LPWSTR Name;
} SORTED_THREAT, * PSORTED_THREAT;

LIST_ENTRY g_CategoryHead;
MP_API MpApiSet;
HANDLE g_DumpHeap = NULL;

static const CAT_NAME CatNameTable[] = {
    { MP_THREAT_CATEGORY_INVALID,                    L"Invalid",                    L"MP_THREAT_CATEGORY_INVALID" },
    { MP_THREAT_CATEGORY_ADWARE,                     L"Adware",                     L"MP_THREAT_CATEGORY_ADWARE" },
    { MP_THREAT_CATEGORY_SPYWARE,                    L"Spyware",                    L"MP_THREAT_CATEGORY_SPYWARE" },
    { MP_THREAT_CATEGORY_PASSWORDSTEALER,            L"PWS",                        L"MP_THREAT_CATEGORY_PASSWORDSTEALER" },
    { MP_THREAT_CATEGORY_TROJANDOWNLOADER,           L"TrojanDownloader",           L"MP_THREAT_CATEGORY_TROJANDOWNLOADER" },
    { MP_THREAT_CATEGORY_WORM,                       L"Worm",                       L"MP_THREAT_CATEGORY_WORM" },
    { MP_THREAT_CATEGORY_BACKDOOR,                   L"Backdoor",                   L"MP_THREAT_CATEGORY_BACKDOOR" },
    { MP_THREAT_CATEGORY_REMOTEACCESSTROJAN,         L"RAT",                        L"MP_THREAT_CATEGORY_REMOTEACCESSTROJAN" },
    { MP_THREAT_CATEGORY_TROJAN,                     L"Trojan",                     L"MP_THREAT_CATEGORY_TROJAN" },
    { MP_THREAT_CATEGORY_EMAILFLOODER,               L"Spammer",                    L"MP_THREAT_CATEGORY_EMAILFLOODER" },
    { MP_THREAT_CATEGORY_KEYLOGGER,                  L"Keylogger",                  L"MP_THREAT_CATEGORY_KEYLOGGER" },
    { MP_THREAT_CATEGORY_DIALER,                     L"Dialer",                     L"MP_THREAT_CATEGORY_DIALER" },
    { MP_THREAT_CATEGORY_MONITORINGSOFTWARE,         L"MonitoringTool",             L"MP_THREAT_CATEGORY_MONITORINGSOFTWARE" },
    { MP_THREAT_CATEGORY_BROWSERMODIFIER,            L"BrowserModifier",            L"MP_THREAT_CATEGORY_BROWSERMODIFIER" },
    { MP_THREAT_CATEGORY_COOKIE,                     L"Cookie",                     L"MP_THREAT_CATEGORY_COOKIE" },
    { MP_THREAT_CATEGORY_BROWSERPLUGIN,              L"BrowserPlugin",              L"MP_THREAT_CATEGORY_BROWSERPLUGIN" },
    { MP_THREAT_CATEGORY_AOLEXPLOIT,                 L"AolExploit",                 L"MP_THREAT_CATEGORY_AOLEXPLOIT" },
    { MP_THREAT_CATEGORY_NUKER,                      L"Nuker",                      L"MP_THREAT_CATEGORY_NUKER" },
    { MP_THREAT_CATEGORY_SECURITYDISABLER,           L"SecurityDisabler",           L"MP_THREAT_CATEGORY_SECURITYDISABLER" },
    { MP_THREAT_CATEGORY_JOKEPROGRAM,                L"Joke",                       L"MP_THREAT_CATEGORY_JOKEPROGRAM" },
    { MP_THREAT_CATEGORY_HOSTILEACTIVEXCONTROL,      L"ActiveX",                    L"MP_THREAT_CATEGORY_HOSTILEACTIVEXCONTROL" },
    { MP_THREAT_CATEGORY_SOFTWAREBUNDLER,            L"SoftwareBundler",            L"MP_THREAT_CATEGORY_SOFTWAREBUNDLER" },
    { MP_THREAT_CATEGORY_STEALTHNOTIFIER,            L"TrojanClicker",              L"MP_THREAT_CATEGORY_STEALTHNOTIFIER" },
    { MP_THREAT_CATEGORY_SETTINGSMODIFIER,           L"SettingsModifier",           L"MP_THREAT_CATEGORY_SETTINGSMODIFIER" },
    { MP_THREAT_CATEGORY_TOOLBAR,                    L"Toolbar",                    L"MP_THREAT_CATEGORY_TOOLBAR" },
    { MP_THREAT_CATEGORY_REMOTECONTROLSOFTWARE,      L"RemoteControlSoftware",      L"MP_THREAT_CATEGORY_REMOTECONTROLSOFTWARE" },
    { MP_THREAT_CATEGORY_TROJANFTP,                  L"TrojanFtp",                  L"MP_THREAT_CATEGORY_TROJANFTP" },
    { MP_THREAT_CATEGORY_POTENTIALUNWANTEDSOFTWARE,  L"PUA",                        L"MP_THREAT_CATEGORY_POTENTIALUNWANTEDSOFTWARE" },
    { MP_THREAT_CATEGORY_ICQEXPLOIT,                 L"IcqExploit",                 L"MP_THREAT_CATEGORY_ICQEXPLOIT" },
    { MP_THREAT_CATEGORY_TROJANTELNET,               L"TrojanTelnet",               L"MP_THREAT_CATEGORY_TROJANTELNET" },
    { MP_THREAT_CATEGORY_EXPLOIT,                    L"Exploit",                    L"MP_THREAT_CATEGORY_EXPLOIT" },
    { MP_THREAT_CATEGORY_FILESHARINGPROGRAM,         L"FileSharing",                L"MP_THREAT_CATEGORY_FILESHARINGPROGRAM" },
    { MP_THREAT_CATEGORY_MALWARE_CREATION_TOOL,      L"Constructor",                L"MP_THREAT_CATEGORY_MALWARE_CREATION_TOOL" },
    { MP_THREAT_CATEGORY_REMOTE_CONTROL_SOFTWARE,    L"RemoteAccess",               L"MP_THREAT_CATEGORY_REMOTE_CONTROL_SOFTWARE" },
    { MP_THREAT_CATEGORY_TOOL,                       L"Tool",                       L"MP_THREAT_CATEGORY_TOOL" },
    { MP_THREAT_CATEGORY_TROJAN_DENIALOFSERVICE,     L"DoS",                        L"MP_THREAT_CATEGORY_TROJAN_DENIALOFSERVICE" },
    { MP_THREAT_CATEGORY_TROJAN_DROPPER,             L"TrojanDropper",              L"MP_THREAT_CATEGORY_TROJAN_DROPPER" },
    { MP_THREAT_CATEGORY_TROJAN_MASSMAILER,          L"MassMailer",                 L"MP_THREAT_CATEGORY_TROJAN_MASSMAILER" },
    { MP_THREAT_CATEGORY_TROJAN_MONITORINGSOFTWARE,  L"TrojanSpy",                  L"MP_THREAT_CATEGORY_TROJAN_MONITORINGSOFTWARE" },
    { MP_THREAT_CATEGORY_TROJAN_PROXYSERVER,         L"TrojanProxy",                L"MP_THREAT_CATEGORY_TROJAN_PROXYSERVER" },
    { MP_THREAT_CATEGORY_RESERVED0,                  L"Reserved0",                  L"MP_THREAT_CATEGORY_RESERVED0" },
    { MP_THREAT_CATEGORY_VIRUS,                      L"Virus",                      L"MP_THREAT_CATEGORY_VIRUS" },
    { MP_THREAT_CATEGORY_KNOWN,                      L"FriendlyFiles",              L"MP_THREAT_CATEGORY_KNOWN" },
    { MP_THREAT_CATEGORY_UNKNOWN,                    L"Unknown",                    L"MP_THREAT_CATEGORY_UNKNOWN" },
    { MP_THREAT_CATEGORY_SPP,                        L"SoftwareProtectionPlatform", L"MP_THREAT_CATEGORY_SPP" },
    { MP_THREAT_CATEGORY_BEHAVIOR,                   L"Behavior",                   L"MP_THREAT_CATEGORY_BEHAVIOR" },
    { MP_THREAT_CATEGORY_VULNERABILTIY,              L"NisVulnerability",           L"MP_THREAT_CATEGORY_VULNERABILTIY" },
    { MP_THREAT_CATEGORY_POLICY,                     L"NisPolicy",                  L"MP_THREAT_CATEGORY_POLICY" },
    { MP_THREAT_CATEGORY_EUS,                        L"EUS",                        L"MP_THREAT_CATEGORY_EUS" },
    { MP_THREAT_CATEGORY_RANSOM,                     L"Ransom",                     L"MP_THREAT_CATEGORY_RANSOM" },
};

/*
* RadixSort
*
* Purpose:
*
* Sort entries list using radix sort.
*
*/
VOID RadixSort(
    _In_ PSORTED_THREAT arr,
    _In_ ULONG n)
{
    if (n <= 1) return;

    PSORTED_THREAT temp = (PSORTED_THREAT)HeapAlloc(g_DumpHeap, HEAP_ZERO_MEMORY, n * sizeof(SORTED_THREAT));
    if (temp == NULL)
        return;

    ULONG count[256];
    PSORTED_THREAT src = arr;
    PSORTED_THREAT dst = temp;

    for (int shift = 0; shift < 32; shift += 8) {
        memset(count, 0, sizeof(count));

        for (ULONG i = 0; i < n; i++) {
            ULONG digit = (src[i].ThreatID >> shift) & 0xFF;
            count[digit]++;
        }

        for (int i = 1; i < 256; i++)
            count[i] += count[i - 1];

        for (LONG i = n - 1; i >= 0; i--) {
            ULONG digit = (src[i].ThreatID >> shift) & 0xFF;
            count[digit]--;
            dst[count[digit]] = src[i];
        }

        PSORTED_THREAT swap = src;
        src = dst;
        dst = swap;
    }

    if (src != arr)
        memcpy(arr, src, n * sizeof(SORTED_THREAT));

    HeapFree(g_DumpHeap, 0, temp);
}

/*
* CatGetName
*
* Purpose:
*
* Get predefined category name.
*
*/
LPCWSTR CatGetName(
    _In_ PCAT Cat,
    _In_ BOOL QueryInternalName
)
{
    ULONG low = 0, mid;
    ULONG high = ARRAYSIZE(CatNameTable) - 1;

    while (low <= high) {
        mid = low + (high - low) / 2;

        if (CatNameTable[mid].Category == Cat->Category)
        {
            if (QueryInternalName) {
                return CatNameTable[mid].InternalName;
            }
            else {
                StringCchCopy(Cat->Name, ARRAYSIZE(Cat->Name), CatNameTable[mid].DisplayName);
                return Cat->Name;
            }
        }
        else if (CatNameTable[mid].Category < Cat->Category) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    StringCchCopy(Cat->Name, ARRAYSIZE(Cat->Name), L"UnknownCategory");
    return L"Unknown Category";
}

/*
* CatExist
*
* Purpose:
*
* Return category if already in list or NULL otherwise.
*
*/
PCAT CatExist(
    _In_ MPTHREAT_CATEGORY Category
)
{
    PCAT catEntry;
    PLIST_ENTRY head, next;

    head = &g_CategoryHead;
    next = head->Flink;

    while ((next != NULL) && (next != head)) {
        catEntry = CONTAINING_RECORD(next, CAT, ListEntry);
        if (catEntry->Category == Category)
            return catEntry;
        next = next->Flink;
    }
    return NULL;
}

/*
* CatAdd
*
* Purpose:
*
* Add new category entry or return existing.
*
*/
PCAT CatAdd(
    _In_ PMPTHREAT_INFO ThreatInfo
)
{
    PCAT catEntry;

    //
    // Check if such category already exist.
    //
    catEntry = CatExist(ThreatInfo->ThreatCategory);
    if (catEntry != NULL)
        return catEntry;

    //
    // Category not found, remember it.
    //
    catEntry = (PCAT)HeapAlloc(g_DumpHeap, HEAP_ZERO_MEMORY, sizeof(CAT));
    if (catEntry) {
        catEntry->Category = ThreatInfo->ThreatCategory;
        CatGetName(catEntry, FALSE);
        InitializeListHead(&catEntry->ThreatEntryHead);
        InsertHeadList(&g_CategoryHead, &catEntry->ListEntry);
    }

    return catEntry;
}

/*
* CatThreatEntryAdd
*
* Purpose:
*
* Add new threat entry for category.
*
*/
VOID CatThreatEntryAdd(
    _In_ MPTHREAT_INFO* MpInfo
)
{
    PTHREAT_ENTRY threatEntry = NULL;
    PCAT catEntry;

    //
    // First add/or query category entry.
    //
    catEntry = CatAdd(MpInfo);
    if (catEntry == NULL)
        return;

    //
    // Next create threat entry and save it into category list.
    //
    threatEntry = (PTHREAT_ENTRY)HeapAlloc(g_DumpHeap, HEAP_ZERO_MEMORY, sizeof(THREAT_ENTRY));
    if (threatEntry) {
        threatEntry->MpInfo = MpInfo;
        InsertHeadList(&catEntry->ThreatEntryHead, &threatEntry->ListEntry);
        catEntry->NumberOfEntries++;
    }
    return;
}

/*
* InitMpAPI
*
* Purpose:
*
* Initialize MpClient API set with routine pointers.
*
*/
BOOL InitMpAPI(
    _In_ HMODULE hMpClient
)
{
    MpApiSet.MpErrorMessageFormat = (pfnMpErrorMessageFormat)GetProcAddress(hMpClient, "MpErrorMessageFormat");
    if (MpApiSet.MpErrorMessageFormat == NULL) return FALSE;

    MpApiSet.MpHandleClose = (pfnMpHandleClose)GetProcAddress(hMpClient, "MpHandleClose");
    if (MpApiSet.MpHandleClose == NULL) return FALSE;

    MpApiSet.MpManagerOpen = (pfnMpManagerOpen)GetProcAddress(hMpClient, "MpManagerOpen");
    if (MpApiSet.MpManagerOpen == NULL) return FALSE;

    MpApiSet.MpFreeMemory = (pfnMpFreeMemory)GetProcAddress(hMpClient, "MpFreeMemory");
    if (MpApiSet.MpFreeMemory == NULL) return FALSE;

    MpApiSet.MpManagerVersionQuery = (pfnMpManagerVersionQuery)GetProcAddress(hMpClient, "MpManagerVersionQuery");
    if (MpApiSet.MpManagerVersionQuery == NULL) return FALSE;

    MpApiSet.MpThreatEnumerate = (pfnMpThreatEnumerate)GetProcAddress(hMpClient, "MpThreatEnumerate");
    if (MpApiSet.MpThreatEnumerate == NULL) return FALSE;

    MpApiSet.MpThreatOpen = (pfnMpThreatOpen)GetProcAddress(hMpClient, "MpThreatOpen");
    if (MpApiSet.MpThreatOpen == NULL) return FALSE;

    MpApiSet.MpThreatQuery = (pfnMpThreatQuery)GetProcAddress(hMpClient, "MpThreatQuery");
    if (MpApiSet.MpThreatQuery == NULL) return FALSE;

    return TRUE;
}

/*
* CatSave
*
* Purpose:
*
* Save category entries to file.
*
*/
VOID CatSave(
    _In_ LPWSTR lpDirectory,
    _In_ PCAT Cat,
    _In_ BOOL Verbose
)
{
    HANDLE hFile;
    PTHREAT_ENTRY threatEntry;
    PLIST_ENTRY nextEntry;
    WCHAR szFilePath[MAX_PATH * 2];
    WCHAR wcBOM = 0xFEFF;
    DWORD written;
    SIZE_T cbLength = 0;

    if (!lpDirectory || !Cat->Name[0])
        return;

    StringCchPrintf(szFilePath, ARRAYSIZE(szFilePath), L"%wS\\%wS.txt", lpDirectory, Cat->Name);

    hFile = CreateFile(szFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    // Write UTF-16 BOM
    WriteFile(hFile, &wcBOM, sizeof(WCHAR), &written, NULL);

    nextEntry = Cat->ThreatEntryHead.Flink;
    while ((nextEntry != NULL) && (nextEntry != &Cat->ThreatEntryHead))
    {
        threatEntry = CONTAINING_RECORD(nextEntry, THREAT_ENTRY, ListEntry);

        if (threatEntry->MpInfo && threatEntry->MpInfo->Name) {

            if (Verbose)
                cuiPrintText(threatEntry->MpInfo->Name, TEXT_COLOR_DEFAULT);

            if (SUCCEEDED(StringCbLength(threatEntry->MpInfo->Name,
                MAX_PATH * sizeof(WCHAR),
                &cbLength)))
            {
                WriteFile(hFile, threatEntry->MpInfo->Name, (DWORD)cbLength, &written, NULL);
                WriteFile(hFile, L"\r\n", 4, &written, NULL);
            }
        }

        nextEntry = nextEntry->Flink;
    }

    CloseHandle(hFile);
}

/*
* CatSaveAllToCSV
*
* Purpose:
*
* Save all threats into single CSV file.
*
*/
BOOL CatSaveAllToCSV(
    _In_ LPWSTR lpDirectory,
    _In_ SIZE_T TotalThreats
)
{
    WCHAR szCsvPath[MAX_PATH * 2];
    HANDLE hFile;
    PCAT catEntry;
    PTHREAT_ENTRY threatEntry;
    PLIST_ENTRY head, nextCat, nextThreat;
    DWORD written;
    SIZE_T cbLength = 0;

    if (TotalThreats == 0) {
        cuiPrintText(L"[!] No threats to save", TEXT_COLOR_DEFAULT);
        return FALSE;
    }

    // Allocate array
    PSORTED_THREAT pSorted = (PSORTED_THREAT)HeapAlloc(g_DumpHeap,
        HEAP_ZERO_MEMORY, TotalThreats * sizeof(SORTED_THREAT));

    if (!pSorted) {
        cuiPrintText(L"[-] Memory allocation failed for sorting", TEXT_COLOR_DEFAULT);
        return FALSE;
    }

    ULONG index = 0;
    head = &g_CategoryHead;
    nextCat = head->Flink;

    while ((nextCat != NULL) && (nextCat != head)) {
        catEntry = CONTAINING_RECORD(nextCat, CAT, ListEntry);
        nextThreat = catEntry->ThreatEntryHead.Flink;
        while ((nextThreat != NULL) && (nextThreat != &catEntry->ThreatEntryHead)) {
            threatEntry = CONTAINING_RECORD(nextThreat, THREAT_ENTRY, ListEntry);

            if (threatEntry->MpInfo && index < TotalThreats) {
                PMPTHREAT_INFO info = threatEntry->MpInfo;

                pSorted[index].CategoryID = info->ThreatCategory;
                pSorted[index].SeverityID = info->ThreatCriticality;
                pSorted[index].ThreatID = info->ThreatID;
                pSorted[index].Name = info->Name ? info->Name : L"";

                index++;
            }
            nextThreat = nextThreat->Flink;
        }
        nextCat = nextCat->Flink;
    }

    RadixSort(pSorted, (ULONG)TotalThreats);
    StringCchPrintf(szCsvPath, ARRAYSIZE(szCsvPath), L"%wS\\defender.csv", lpDirectory);

    hFile = CreateFile(szCsvPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cuiPrintText(L"[-] Failed to create AllThreats.csv", TEXT_COLOR_DEFAULT);
        HeapFree(g_DumpHeap, 0, pSorted);
        return FALSE;
    }

    CHAR szLine[1024];

    if (SUCCEEDED(StringCchCopyA(szLine, ARRAYSIZE(szLine),
        "CategoryID,SeverityID,ThreatID,ThreatName\r\n")))
    {
        if (SUCCEEDED(StringCbLengthA(szLine, sizeof(szLine), &cbLength))) {

            WriteFile(hFile, szLine, (DWORD)cbLength, &written, NULL);
            for (ULONG i = 0; i < TotalThreats; i++) {

                CHAR szNameA[512] = { 0 };
                if (pSorted[i].Name && *pSorted[i].Name) {
                    WideCharToMultiByte(CP_ACP, 0, pSorted[i].Name, -1,
                        szNameA, ARRAYSIZE(szNameA), NULL, NULL);
                }

                StringCchPrintfA(szLine, ARRAYSIZE(szLine), "%lu,%lu,%lu,%s\r\n",
                    pSorted[i].CategoryID,
                    pSorted[i].SeverityID,
                    pSorted[i].ThreatID,
                    szNameA);

                if (SUCCEEDED(StringCbLengthA(szLine, sizeof(szLine), &cbLength))) {
                    WriteFile(hFile, szLine, (DWORD)cbLength, &written, NULL);
                }
            }
        }
    }

    CloseHandle(hFile);
    HeapFree(g_DumpHeap, 0, pSorted);

    return TRUE;
}

/*
* MpShowLastErrorDebug
*
* Purpose:
*
* Convert last MP error to text and display it.
*
*/
VOID MpShowLastErrorDebug(
    _In_ MPHANDLE MpHandle,
    _In_ HRESULT hr
)
{
    LPWSTR lastError;

    cuiPrintText(L"[!] Unexpected error from MpClient call", TEXT_COLOR_DEFAULT);
    if (MpApiSet.MpErrorMessageFormat(MpHandle, hr, &lastError) == S_OK) {
        cuiPrintText(lastError, TEXT_COLOR_DEFAULT);
        MpApiSet.MpFreeMemory(lastError);
    }
}

/*
* PrintComponentVersion
*
* Purpose:
*
* Output WD component versions.
*
*/
VOID PrintComponentVersion(
    _In_ LPWSTR Component,
    _In_ ULONGLONG ComponentVersion
)
{
    WCHAR szBuffer[100];
    ULARGE_INTEGER ver;
    ver.QuadPart = ComponentVersion;
    StringCchPrintf(szBuffer, ARRAYSIZE(szBuffer), L"%wS%lu.%lu.%lu.%lu",
        Component,
        HIWORD(ver.HighPart), LOWORD(ver.HighPart),
        HIWORD(ver.LowPart), LOWORD(ver.LowPart));

    cuiPrintText(szBuffer, TEXT_COLOR_DEFAULT);
}

/*
* main
*
* Purpose:
*
* Program entrypoint.
*
*/
VOID main()
{
    BOOL bCatsReady = FALSE;
    HMODULE hMpClient = NULL;
    WCHAR szBuffer[MAX_PATH * 2];

    MPHANDLE MpHandle = NULL, ThreatEnumHandle = NULL;
    HRESULT hr, ehr = S_FALSE;

    PMPTHREAT_INFO ThreatInfo;
    MPVERSION_INFO MpVersion;

    PWSTR lpProgramFiles = NULL, dllPath;

    SIZE_T programFilesLength = 0, totalLength, totalThreats = 0;

    __security_init_cookie();
    MpVersion.AVSignature.Version = 0;

    //
    // Create designated heap for enumeration.
    //
    g_DumpHeap = HeapCreate(0, 0, 0);
    if (g_DumpHeap == NULL) {
        ExitProcess(ERROR_ASSERTION_FAILURE);
    }

    //
    // Init console output.
    //
    cuiInit();
    cuiPrintText(L"[+] MpEnum (Takanami) v2.0.0.2604 (c) 2018 - 2026 hfiref0x", TEXT_COLOR_DEFAULT);

    //
    // Build path to MpClient.dll and load it.
    //
#if defined (__cplusplus)
    if (SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, NULL, &lpProgramFiles) != S_OK) {
#else
    if (SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, NULL, &lpProgramFiles) != S_OK) {
#endif
        cuiPrintText(L"[!] SHGetKnownFolderPath->Unexpected error\r\n", TEXT_COLOR_DEFAULT);
        ExitProcess(ERROR_ASSERTION_FAILURE);
    }

    totalLength = MAX_PATH;
    if (SUCCEEDED(StringCchLength(lpProgramFiles, MAX_PATH, &programFilesLength)))
        totalLength += programFilesLength;

    dllPath = (PWSTR)HeapAlloc(g_DumpHeap, HEAP_ZERO_MEMORY, totalLength * sizeof(WCHAR));
    if (dllPath == NULL) {
        cuiPrintText(L"[!] HeapAlloc->Unexpected error\r\n", TEXT_COLOR_DEFAULT);
        ExitProcess(ERROR_ASSERTION_FAILURE);
    }

    StringCchPrintf(dllPath, totalLength, L"%wS\\Windows Defender\\MpClient.dll", lpProgramFiles);
    hMpClient = LoadLibraryEx(dllPath, NULL, 0);
    if (hMpClient == NULL) {
        cuiPrintText(L"[!] LoadLibraryExW(MpClient)->Unexpected error\r\n", TEXT_COLOR_DEFAULT);
#ifndef _DEBUG
        ExitProcess(ERROR_ASSERTION_FAILURE);
#endif
    }

    cuiPrintText(L"[+] MpClient.dll loaded for cats", TEXT_COLOR_DEFAULT);

    //
    // Load routine pointers.
    // 
    if (!InitMpAPI(hMpClient)) {
        cuiPrintText(L"[!] InitMpAPI->Unexpected error\r\n", TEXT_COLOR_DEFAULT);
#ifndef _DEBUG
        ExitProcess(ERROR_ASSERTION_FAILURE);
#endif
    }

    //
    // Open MpClient manager.
    //
    hr = MpApiSet.MpManagerOpen(0, &MpHandle);
    if (SUCCEEDED(hr)) {

        cuiPrintText(L"[+] MpManagerOpen success", TEXT_COLOR_DEFAULT);

        //
        // Query what version we are using. 
        // Note: old outdated shit from Win7 is generally incompatible with definitions we use/have.
        //
        RtlSecureZeroMemory(&MpVersion, sizeof(MpVersion));
        hr = MpApiSet.MpManagerVersionQuery(MpHandle, &MpVersion);
        if (SUCCEEDED(hr)) {
            cuiPrintText(L"[+] MpManagerVersionQuery success", TEXT_COLOR_DEFAULT);
            cuiPrintText(L"[+] Product information\r\n", TEXT_COLOR_DEFAULT);
            PrintComponentVersion(L"Product:           ", MpVersion.Product.Version);
            PrintComponentVersion(L"Engine:            ", MpVersion.Engine.Version);
            PrintComponentVersion(L"Service:           ", MpVersion.Service.Version);
            PrintComponentVersion(L"AV Signature:      ", MpVersion.AVSignature.Version);
            PrintComponentVersion(L"AS Signature:      ", MpVersion.ASSignature.Version);
            PrintComponentVersion(L"FileSystem Filter: ", MpVersion.FileSystemFilter.Version);
            PrintComponentVersion(L"NIS Engine:        ", MpVersion.NISEngine.Version);
            PrintComponentVersion(L"NIS Signature:     ", MpVersion.NISSignature.Version);
        }
        else {
            MpShowLastErrorDebug(MpHandle, hr);
        }

        //
        // Open signature DB for enumeration.
        //
        hr = MpApiSet.MpThreatOpen(MpHandle,
            MPTHREAT_SOURCE_SIGNATURE,
            MPTHREAT_TYPE_KNOWNBAD,
            &ThreatEnumHandle);

        if (SUCCEEDED(hr)) {

            cuiPrintText(L"\r\n[+] MpThreatOpen success, enumerating...", TEXT_COLOR_DEFAULT);
            InitializeListHead(&g_CategoryHead);

            //
            // Enumerate all entries in DB and move them into cats.
            //
            do {
                __try {
                    ThreatInfo = NULL;
                    ehr = MpApiSet.MpThreatEnumerate(ThreatEnumHandle, &ThreatInfo);
                    if (ehr == S_OK) {
                        CatThreatEntryAdd(ThreatInfo);
                    }
                    else {
                        if (ehr != S_FALSE) {
                            cuiPrintText(L"[!] MpThreatEnumerate->Unexpected failure\r\n", TEXT_COLOR_DEFAULT);
                            break;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    OutputDebugString(L"ex\r\n");
                }

            } while (ehr != S_FALSE);

            cuiPrintText(L"[+] Threats enumeration complete", TEXT_COLOR_DEFAULT);

            bCatsReady = TRUE;

            MpApiSet.MpHandleClose(ThreatEnumHandle);
        }
        else {

            MpShowLastErrorDebug(MpHandle, hr);

        }

        MpApiSet.MpHandleClose(MpHandle);
    }
    else {

        MpShowLastErrorDebug(MpHandle, hr);

    }

    //
    // Output results and save our cats.
    //
    if (bCatsReady)
    {
        WCHAR szDirectory[MAX_PATH * 2] = { 0 };
        WCHAR szVersionDir[MAX_PATH * 2] = { 0 };
        ULARGE_INTEGER ver = { 0 };

        if (!GetCurrentDirectory(ARRAYSIZE(szDirectory), szDirectory))
        {
            cuiPrintText(L"[-] Failed to get current directory", TEXT_COLOR_DEFAULT);
            StringCchCopy(szDirectory, ARRAYSIZE(szDirectory), L".");
        }

        ver.QuadPart = MpVersion.AVSignature.Version;

        StringCchPrintf(szVersionDir, ARRAYSIZE(szVersionDir),
            L"%wS\\%lu.%lu.%lu.%lu",
            szDirectory,
            HIWORD(ver.HighPart), LOWORD(ver.HighPart),
            HIWORD(ver.LowPart), LOWORD(ver.LowPart));

        CreateDirectory(szVersionDir, NULL);

        cuiPrintText(L"[+] Saving threat database...", TEXT_COLOR_DEFAULT);

        PCAT catEntry;
        PLIST_ENTRY head, next;
        head = &g_CategoryHead;
        next = head->Flink;

        while ((next != NULL) && (next != head))
        {
            catEntry = CONTAINING_RECORD(next, CAT, ListEntry);

            totalThreats += catEntry->NumberOfEntries;

            StringCchPrintf(szBuffer, ARRAYSIZE(szBuffer),
                L"    -> %wS (%llu threats)", catEntry->Name, catEntry->NumberOfEntries);

            cuiPrintText(szBuffer, TEXT_COLOR_DEFAULT);

            //CatSave(szVersionDir, catEntry, FALSE);
            next = next->Flink;
        }

        //
        // Save database into ANSI CSV file.
        //
        if (CatSaveAllToCSV(szVersionDir, totalThreats))
            cuiPrintText(L"[+] All threats saved to defender.csv", TEXT_COLOR_DEFAULT);

        StringCchPrintf(szBuffer, ARRAYSIZE(szBuffer),
            L"[+] Total threats dumped: %llu", totalThreats);
        cuiPrintText(szBuffer, TEXT_COLOR_DEFAULT);
    }

    //
    // Cleanup (unnecessary).
    //
    HeapDestroy(g_DumpHeap);
    FreeLibrary(hMpClient);
    CoTaskMemFree(lpProgramFiles);
    cuiPrintText(L"[+] Bye!", TEXT_COLOR_DEFAULT);
    ExitProcess(0);
}
