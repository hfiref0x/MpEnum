/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2026
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     2.00
*
*  DATE:        15 Apr 2026
*
*  Common include header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#include <windows.h>
#include <ShlObj.h>
#include <strsafe.h>
#include "MpClient.h"
#include "cui.h"

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#pragma warning(disable: 6320) //Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER.

typedef struct _MP_API {
    pfnMpManagerOpen MpManagerOpen;
    pfnMpHandleClose MpHandleClose;
    pfnMpFreeMemory  MpFreeMemory;
    pfnMpThreatOpen  MpThreatOpen;
    pfnMpThreatQuery MpThreatQuery;
    pfnMpThreatEnumerate MpThreatEnumerate;
    pfnMpErrorMessageFormat MpErrorMessageFormat;
    pfnMpManagerVersionQuery MpManagerVersionQuery;
} MP_API, * PMP_API;

#define TEXT_COLOR_DEFAULT (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED)

FORCEINLINE
VOID
InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
    return;
}

FORCEINLINE
VOID
InitializeListHead(
    _Out_ PLIST_ENTRY ListHead
)
{
    ListHead->Flink = ListHead->Blink = ListHead;
    return;
}
