/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.01
*
*  DATE:        29 Nov 2018
*
*  Common include header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <windows.h>
#include <ShlObj.h>
#include <VersionHelpers.h>
#include "minirtl\minirtl.h"
#include "MpClient.h"
#include "cui.h"

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1910)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#pragma once

typedef struct _MP_API {
    pfnMpManagerOpen MpManagerOpen;
    pfnMpHandleClose MpHandleClose;
    pfnMpFreeMemory  MpFreeMemory;
    pfnMpScanStart   MpScanStart;
    pfnMpScanControl MpScanControl;
    pfnMpThreatOpen  MpThreatOpen;
    pfnMpThreatQuery MpThreatQuery;
    pfnMpThreatEnumerate MpThreatEnumerate;
    pfnMpErrorMessageFormat MpErrorMessageFormat;
    pfnMpManagerVersionQuery MpManagerVersionQuery;
    pfnWDStatus WDStatus;
} MP_API, *PMP_API;
