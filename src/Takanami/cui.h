/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2026
*
*  TITLE:       CUI.H
*
*  VERSION:     2.00
*
*  DATE:        16 Apr 2026
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

BOOL cuiInit(
    VOID);

VOID cuiPrintText2(
    _In_ LPCWSTR lpMessage,
    _In_ WORD wColor);

VOID cuiPrintText(
    _In_ LPCWSTR lpMessage,
    _In_ WORD wColor);
