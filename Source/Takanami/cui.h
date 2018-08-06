/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       CUI.H
*
*  VERSION:     1.30
*
*  DATE:        01 Aug 2018
*
*  Common header file for console ui.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

VOID cuiInitialize(
    _In_ BOOL InitInput,
    _Out_opt_ PBOOL IsConsoleOutput
    );

VOID cuiPrintText(
	_In_ LPWSTR lpText,
	_In_ BOOL UseReturn
	);

VOID cuiPrintTextLastError(
    _In_ BOOL UseReturn
    );
