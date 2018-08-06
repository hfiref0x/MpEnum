/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        01 Aug 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

typedef struct _CAT_ENTRY {
    struct _CAT_ENTRY *Next;
    MPTHREAT_INFO *MpInfo;
} CAT_ENTRY, *PCAT_ENTRY;

typedef struct _CAT {
    struct _CAT *Next;
    MPTHREAT_CATEGORY Category;
    ULONG_PTR NumberOfEntries;
    CAT_ENTRY CatEntryHead;
    WCHAR Name[MAX_PATH];
} CAT, *PCAT;

CAT g_CategoryHead;
MP_API MpApiSet;
HANDLE g_DumpHeap = NULL;

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
    PCAT CatEntry;

    CatEntry = &g_CategoryHead;

    while (CatEntry) {
        if (CatEntry->Category == Category)
            return CatEntry;
        CatEntry = CatEntry->Next;
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
    PCAT CatEntry;
    SIZE_T i, k;

    CatEntry = CatExist(ThreatInfo->ThreatCategory);
    if (CatEntry != NULL)
        return CatEntry;

    CatEntry = &g_CategoryHead;
    while (CatEntry->Next != NULL)
        CatEntry = CatEntry->Next;

    CatEntry->Next = HeapAlloc(g_DumpHeap, HEAP_ZERO_MEMORY, sizeof(CAT));
    if (CatEntry->Next == NULL)
        return NULL;

    CatEntry = CatEntry->Next;
    CatEntry->Category = ThreatInfo->ThreatCategory;

    if (ThreatInfo->ThreatCategory == MP_THREAT_CATEGORY_INVALID) {
        _strcpy(CatEntry->Name, L"Invalid");
    }
    else {
        k = _strlen(ThreatInfo->Name);

        for (i = 0; i < k; i++) {
            if (ThreatInfo->Name[i] == L':')
                break;
        }

        _strncpy(CatEntry->Name, MAX_PATH, ThreatInfo->Name, i);

    }
    return CatEntry;
}

/*
* CatEntryAdd
*
* Purpose:
*
* Add new entry for category.
*
*/
PCAT_ENTRY CatEntryAdd(
    _In_ MPTHREAT_INFO *MpInfo
)
{
    PCAT Cat;
    PCAT_ENTRY Entry = NULL;

    __try {

        Cat = CatAdd(MpInfo);
        if (Cat == NULL)
            return NULL;

        Entry = &Cat->CatEntryHead;
        while (Entry->Next != NULL)
            Entry = Entry->Next;

        Entry->Next = HeapAlloc(g_DumpHeap, HEAP_ZERO_MEMORY, sizeof(CAT_ENTRY));
        if (Entry->Next == NULL)
            return NULL;

        Entry = Entry->Next;
        Entry->MpInfo = MpInfo;
        Cat->NumberOfEntries++;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
       //nothing
    }
    return Entry;
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
    _In_ HANDLE hMpClient
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

    MpApiSet.MpScanControl = (pfnMpScanControl)GetProcAddress(hMpClient, "MpScanControl");
    if (MpApiSet.MpScanControl == NULL) return FALSE;

    MpApiSet.MpScanStart = (pfnMpScanStart)GetProcAddress(hMpClient, "MpScanStart");
    if (MpApiSet.MpScanStart == NULL) return FALSE;

    MpApiSet.MpThreatEnumerate = (pfnMpThreatEnumerate)GetProcAddress(hMpClient, "MpThreatEnumerate");
    if (MpApiSet.MpThreatEnumerate == NULL) return FALSE;

    MpApiSet.MpThreatOpen = (pfnMpThreatOpen)GetProcAddress(hMpClient, "MpThreatOpen");
    if (MpApiSet.MpThreatOpen == NULL) return FALSE;

    MpApiSet.MpThreatQuery = (pfnMpThreatQuery)GetProcAddress(hMpClient, "MpThreatQuery");
    if (MpApiSet.MpThreatQuery == NULL) return FALSE;

    MpApiSet.WDStatus = (pfnWDStatus)GetProcAddress(hMpClient, "WDStatus");
    if (MpApiSet.WDStatus == NULL) return FALSE;

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
    _In_ PCAT Cat
)
{
    BOOL bSuccess = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PCAT_ENTRY Entry;
    LPWSTR lpFileName, Name;
    SIZE_T Length;
    DWORD bytesIO;

    WCHAR  wcBE = 0xFEFF;
    WCHAR  szBuffer[2] = { '\r', '\n' };

    __try {

        Length = _strlen(Cat->Name);
        lpFileName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (MAX_PATH + Length) * sizeof(WCHAR));
        if (lpFileName) {

            _strcpy(lpFileName, Cat->Name);
            _strcat(lpFileName, TEXT(".txt"));

            hFile = CreateFile(lpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {

                WriteFile(hFile, &wcBE, sizeof(WCHAR), &bytesIO, NULL);

                Entry = &Cat->CatEntryHead;
                Entry = Entry->Next;

                while (Entry) {
                    if (Entry->MpInfo) {
                        Name = Entry->MpInfo->Name;
                        if (Name) {
                            cuiPrintText(Name, TRUE);
                            bytesIO = (DWORD)(1 + _strlen(Name)) * sizeof(WCHAR);
                            WriteFile(hFile, Name, bytesIO, &bytesIO, NULL);
                            WriteFile(hFile, szBuffer, sizeof(szBuffer), &bytesIO, NULL);
                        }
                        MpApiSet.MpFreeMemory(Entry->MpInfo);
                    }
                    Entry = Entry->Next;
                }
                bSuccess = TRUE;

                CloseHandle(hFile);
            }
            HeapFree(GetProcessHeap(), 0, lpFileName);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        bSuccess = FALSE;
        cuiPrintText(L"[!] CatSave->Exception\r\n", TRUE);
    }

    if (!bSuccess) cuiPrintText(L"[!] CatSave->Error\r\n", TRUE);
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

    if (MpApiSet.MpErrorMessageFormat(MpHandle, hr, &lastError) == S_OK) {
        cuiPrintText(L"[!] Unexpected error from MpClient call\r\n", TRUE);
        cuiPrintText(lastError, TRUE);
        OutputDebugString(lastError);
        MpApiSet.MpFreeMemory(lastError);
    }
}

VOID PrintComponentVersion(
    _In_ LPWSTR Component,
    _In_ ULONGLONG ComponentVersion
)
{
    WCHAR szBuffer[100];

    WCHAR wMajor, wMinor, wBuild, wRevision;
    ULARGE_INTEGER ver;

    ver.QuadPart = ComponentVersion;

    wMajor = HIWORD(ver.HighPart);
    wMinor = LOWORD(ver.HighPart);

    wBuild = HIWORD(ver.LowPart);
    wRevision = LOWORD(ver.LowPart);

    _strcpy(szBuffer, Component);
    ultostr((ULONG)wMajor, _strend(szBuffer));
    _strcat(szBuffer, L".");
    ultostr((ULONG)wMinor, _strend(szBuffer));
    _strcat(szBuffer, L".");
    ultostr((ULONG)wBuild, _strend(szBuffer));
    _strcat(szBuffer, L".");
    ultostr((ULONG)wRevision, _strend(szBuffer));
    cuiPrintText(szBuffer, TRUE);
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
    HANDLE hMpClient = NULL;
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szProgramFiles[MAX_PATH];

    MPHANDLE MpHandle = NULL, ThreatEnumHandle = NULL;
    HRESULT hr, ehr = S_FALSE;

    PMPTHREAT_INFO ThreatInfo;
    MPVERSION_INFO MpVersion;

    LPWSTR lastError = NULL, lpCategory = NULL;

    PCAT Cat;

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
    cuiInitialize(FALSE, NULL);

    cuiPrintText(L"[+] Takanami v1.0.0.1808", TRUE);
    
    if (!IsWindows8OrGreater()) {

        if (MessageBox(GetForegroundWindow(), L"You need at least Windows 8, continue?",
            NULL, MB_YESNO) != IDYES)
        {
            cuiPrintText(L"[~] Unexpected version", TRUE);
            ExitProcess(ERROR_UNSUPPORTED_TYPE);
        }

    }

    //
    // Build path to MpClient.dll and load it.
    //
    if (!SHGetSpecialFolderPath(NULL,
        szProgramFiles,
        CSIDL_PROGRAM_FILES,
        FALSE))
    {
        cuiPrintText(L"[!] SHGetSpecialFolderPath->Unexpected error\r\n", TRUE);
        ExitProcess(ERROR_ASSERTION_FAILURE);
    }

    _strcpy(szBuffer, szProgramFiles);
    _strcat(szBuffer, TEXT("\\Windows Defender\\MpClient.dll"));

    hMpClient = LoadLibraryEx(szBuffer, NULL, 0);
    if (hMpClient == NULL) {
        cuiPrintText(L"[!] LoadLibraryExW(MpClient)->Unexpected error\r\n", TRUE);
        ExitProcess(ERROR_ASSERTION_FAILURE);
    }

    cuiPrintText(L"[+] MpClient.dll loaded for cats", TRUE);

    //
    // Load routine pointers.
    // 
    if (!InitMpAPI(hMpClient)) {
        cuiPrintText(L"[!] InitMpAPI->Unexpected error\r\n", TRUE);
        ExitProcess(ERROR_ASSERTION_FAILURE);
    }

    //
    // Open MpClient manager.
    //

    hr = MpApiSet.MpManagerOpen(0, &MpHandle);
    if (SUCCEEDED(hr)) {

        cuiPrintText(L"[+] MpManagerOpen success", TRUE);

        //
        // Query what version we are using. 
        // Note: old outdated shit from Win7 is generally incompatible with definitions we use/have.
        //
        RtlSecureZeroMemory(&MpVersion, sizeof(MpVersion));
        hr = MpApiSet.MpManagerVersionQuery(MpHandle, &MpVersion);
        if (SUCCEEDED(hr)) {
            cuiPrintText(L"[+] MpManagerVersionQuery success", TRUE);
            cuiPrintText(L"[+] Product information\r\n", TRUE);
            PrintComponentVersion(L"Product: ", MpVersion.Product.Version);
            PrintComponentVersion(L"Engine: ", MpVersion.Engine.Version);
            PrintComponentVersion(L"Service: ", MpVersion.Service.Version);
            PrintComponentVersion(L"AV Signature: ", MpVersion.AVSignature.Version);
            PrintComponentVersion(L"AS Signature: ", MpVersion.ASSignature.Version);
            PrintComponentVersion(L"FileSystem Filter: ", MpVersion.FileSystemFilter.Version);
            PrintComponentVersion(L"NIS Engine: ", MpVersion.NISEngine.Version);
            PrintComponentVersion(L"NIS Signature: ", MpVersion.NISSignature.Version);
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

            cuiPrintText(L"[+] MpThreatOpen success, enumerating...", TRUE);

            //
            // Enumerate all entries in DB and move them into cats.
            //
            do {
                __try {
                    ThreatInfo = NULL;
                    ehr = MpApiSet.MpThreatEnumerate(ThreatEnumHandle, &ThreatInfo);
                    if ((ehr == S_OK) && (ThreatInfo)) {
                        CatEntryAdd(ThreatInfo);
                    }
                    else {
#ifdef _DEBUG
                        if (ehr != S_FALSE) {
                            cuiPrintText(L"[!] MpThreatEnumerate->Unexpected failure\r\n", TRUE);
                        }
#endif
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef _DEBUG
                    OutputDebugString(L"ex\r\n");
#endif
                }

            } while (ehr != S_FALSE);

            cuiPrintText(L"[+] Threats enumeration complete", TRUE);

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

    cuiPrintText(L"[+] Listing cats...", TRUE);
    Sleep(1000);

    Cat = &g_CategoryHead;
    Cat = Cat->Next;
    while (Cat) {
        szBuffer[0] = 0;
        ultostr(Cat->Category, &szBuffer[0]);
        _strcat(szBuffer, L"\t");

        switch (Cat->Category) {
        case MP_THREAT_CATEGORY_ADWARE:
            lpCategory = L"MP_THREAT_CATEGORY_ADWARE";
            break;
        case MP_THREAT_CATEGORY_SPYWARE:
            lpCategory = L"MP_THREAT_CATEGORY_SPYWARE";
            break;
        case MP_THREAT_CATEGORY_PASSWORDSTEALER:
            lpCategory = L"MP_THREAT_CATEGORY_PASSWORDSTEALER";
            break;
        case MP_THREAT_CATEGORY_TROJANDOWNLOADER:
            lpCategory = L"MP_THREAT_CATEGORY_TROJANDOWNLOADER";
            break;
        case MP_THREAT_CATEGORY_WORM:
            lpCategory = L"MP_THREAT_CATEGORY_WORM";
            break;
        case MP_THREAT_CATEGORY_BACKDOOR:
            lpCategory = L"MP_THREAT_CATEGORY_BACKDOOR";
            break;
        case MP_THREAT_CATEGORY_REMOTEACCESSTROJAN:
            lpCategory = L"MP_THREAT_CATEGORY_REMOTEACCESSTROJAN";
            break;
        case MP_THREAT_CATEGORY_TROJAN:
            lpCategory = L"MP_THREAT_CATEGORY_TROJAN";
            break;
        case MP_THREAT_CATEGORY_EMAILFLOODER:
            lpCategory = L"MP_THREAT_CATEGORY_EMAILFLOODER";
            break;
        case MP_THREAT_CATEGORY_KEYLOGGER:
            lpCategory = L"MP_THREAT_CATEGORY_KEYLOGGER";
            break;
        case MP_THREAT_CATEGORY_DIALER:
            lpCategory = L"MP_THREAT_CATEGORY_DIALER";
            break;
        case MP_THREAT_CATEGORY_MONITORINGSOFTWARE:
            lpCategory = L"MP_THREAT_CATEGORY_MONITORINGSOFTWARE";
            break;
        case MP_THREAT_CATEGORY_BROWSERMODIFIER:
            lpCategory = L"MP_THREAT_CATEGORY_BROWSERMODIFIER";
            break;
        case MP_THREAT_CATEGORY_COOKIE:
            lpCategory = L"MP_THREAT_CATEGORY_COOKIE";
            break;
        case MP_THREAT_CATEGORY_BROWSERPLUGIN:
            lpCategory = L"MP_THREAT_CATEGORY_BROWSERPLUGIN";
            break;
        case MP_THREAT_CATEGORY_AOLEXPLOIT:
            lpCategory = L"MP_THREAT_CATEGORY_AOLEXPLOIT";
            break;
        case MP_THREAT_CATEGORY_NUKER:
            lpCategory = L"MP_THREAT_CATEGORY_NUKER";
            break;
        case MP_THREAT_CATEGORY_SECURITYDISABLER:
            lpCategory = L"MP_THREAT_CATEGORY_SECURITYDISABLER";
            break;
        case MP_THREAT_CATEGORY_JOKEPROGRAM:
            lpCategory = L"MP_THREAT_CATEGORY_JOKEPROGRAM";
            break;
        case MP_THREAT_CATEGORY_HOSTILEACTIVEXCONTROL:
            lpCategory = L"MP_THREAT_CATEGORY_HOSTILEACTIVEXCONTROL";
            break;
        case MP_THREAT_CATEGORY_SOFTWAREBUNDLER:
            lpCategory = L"MP_THREAT_CATEGORY_SOFTWAREBUNDLER";
            break;
        case MP_THREAT_CATEGORY_STEALTHNOTIFIER:
            lpCategory = L"MP_THREAT_CATEGORY_STEALTHNOTIFIER";
            break;
        case MP_THREAT_CATEGORY_SETTINGSMODIFIER:
            lpCategory = L"MP_THREAT_CATEGORY_SETTINGSMODIFIER";
            break;
        case MP_THREAT_CATEGORY_TOOLBAR:
            lpCategory = L"MP_THREAT_CATEGORY_TOOLBAR";
            break;
        case MP_THREAT_CATEGORY_REMOTECONTROLSOFTWARE:
            lpCategory = L"MP_THREAT_CATEGORY_REMOTECONTROLSOFTWARE";
            break;
        case MP_THREAT_CATEGORY_TROJANFTP:
            lpCategory = L"MP_THREAT_CATEGORY_TROJANFTP";
            break;
        case MP_THREAT_CATEGORY_POTENTIALUNWANTEDSOFTWARE:
            lpCategory = L"MP_THREAT_CATEGORY_POTENTIALUNWANTEDSOFTWARE";
            break;
        case MP_THREAT_CATEGORY_ICQEXPLOIT:
            lpCategory = L"MP_THREAT_CATEGORY_ICQEXPLOIT";
            break;
        case MP_THREAT_CATEGORY_TROJANTELNET:
            lpCategory = L"MP_THREAT_CATEGORY_TROJANTELNET";
            break;
        case MP_THREAT_CATEGORY_EXPLOIT:
            lpCategory = L"MP_THREAT_CATEGORY_EXPLOIT";
            break;
        case MP_THREAT_CATEGORY_FILESHARINGPROGRAM:
            lpCategory = L"MP_THREAT_CATEGORY_FILESHARINGPROGRAM";
            break;
        case MP_THREAT_CATEGORY_MALWARE_CREATION_TOOL:
            lpCategory = L"MP_THREAT_CATEGORY_MALWARE_CREATION_TOOL";
            break;
        case MP_THREAT_CATEGORY_REMOTE_CONTROL_SOFTWARE:
            lpCategory = L"MP_THREAT_CATEGORY_REMOTE_CONTROL_SOFTWARE";
            break;
        case MP_THREAT_CATEGORY_TOOL:
            lpCategory = L"MP_THREAT_CATEGORY_TOOL";
            break;
        case MP_THREAT_CATEGORY_TROJAN_DENIALOFSERVICE:
            lpCategory = L"MP_THREAT_CATEGORY_TROJAN_DENIALOFSERVICE";
            break;
        case MP_THREAT_CATEGORY_TROJAN_DROPPER:
            lpCategory = L"MP_THREAT_CATEGORY_TROJAN_DROPPER";
            break;
        case MP_THREAT_CATEGORY_TROJAN_MASSMAILER:
            lpCategory = L"MP_THREAT_CATEGORY_TROJAN_MASSMAILER";
            break;
        case MP_THREAT_CATEGORY_TROJAN_MONITORINGSOFTWARE:
            lpCategory = L"MP_THREAT_CATEGORY_TROJAN_MONITORINGSOFTWARE";
            break;
        case MP_THREAT_CATEGORY_TROJAN_PROXYSERVER:
            lpCategory = L"MP_THREAT_CATEGORY_TROJAN_PROXYSERVER";
            break;
        case MP_THREAT_CATEGORY_VIRUS:
            lpCategory = L"MP_THREAT_CATEGORY_VIRUS";
            break;
        case MP_THREAT_CATEGORY_KNOWN:
            lpCategory = L"MP_THREAT_CATEGORY_KNOWN";
            break;
        case MP_THREAT_CATEGORY_UNKNOWN:
            lpCategory = L"MP_THREAT_CATEGORY_UNKNOWN";
            break;
        case MP_THREAT_CATEGORY_SPP:
            lpCategory = L"MP_THREAT_CATEGORY_SPP";
            break;
        case MP_THREAT_CATEGORY_BEHAVIOR:
            lpCategory = L"MP_THREAT_CATEGORY_BEHAVIOR";
            break;
        case MP_THREAT_CATEGORY_VULNERABILTIY:
            lpCategory = L"MP_THREAT_CATEGORY_VULNERABILTIY";
            break;
        case MP_THREAT_CATEGORY_POLICY:
            lpCategory = L"MP_THREAT_CATEGORY_POLICY";
            break;
        case MP_THREAT_CATEGORY_EUS:
            lpCategory = L"MP_THREAT_CATEGORY_EUS";
            break;
        case MP_THREAT_CATEGORY_RANSOM:
            lpCategory = L"MP_THREAT_CATEGORY_RANSOM";
            break;
        case MP_THREAT_CATEGORY_INVALID:
            lpCategory = L"MP_THREAT_CATEGORY_INVALID";
            break;
        default:
            lpCategory = L"Unknown Category";
            break;
        }

        u64tostr(Cat->NumberOfEntries, _strend(szBuffer));
        _strcat(szBuffer, L"\t");
        _strcat(szBuffer, Cat->Name);

        _strcat(szBuffer, L"\n\r");
        _strcat(szBuffer, lpCategory);

        cuiPrintText(szBuffer, TRUE);

        cuiPrintText(L"[+] Saving cat...", TRUE);
        Sleep(1000);
        CatSave(Cat);
        Cat = Cat->Next;
    }

    //
    // Cleanup (unnecessary).
    //
    HeapDestroy(g_DumpHeap);
    FreeLibrary(hMpClient);
    cuiPrintText(L"[+] Bye!", TRUE);
    ExitProcess(0);
}
