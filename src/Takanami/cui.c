/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2026
*
*  TITLE:       CUI.C
*
*  VERSION:     2.00
*
*  DATE:        16 Apr 2026
*
*  Console output.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

static HANDLE g_hConsoleOutput = INVALID_HANDLE_VALUE;

BOOL cuiInit(
    VOID)
{
    COORD coordScreen = { 0, 0 };
    DWORD cCharsWritten;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD dwConSize;

    g_hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_hConsoleOutput == INVALID_HANDLE_VALUE)
        return FALSE;

    if (!GetConsoleScreenBufferInfo(g_hConsoleOutput, &csbi))
        return FALSE;

    // Enable virtual terminal processing + Unicode support (Windows 10+)
    DWORD dwMode = 0;
    GetConsoleMode(g_hConsoleOutput, &dwMode);
    SetConsoleMode(g_hConsoleOutput, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
        ENABLE_PROCESSED_OUTPUT);

    SetConsoleTextAttribute(g_hConsoleOutput, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);

    dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

    FillConsoleOutputCharacter(g_hConsoleOutput, L' ', dwConSize, coordScreen, &cCharsWritten);
    FillConsoleOutputAttribute(g_hConsoleOutput, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten);
    SetConsoleCursorPosition(g_hConsoleOutput, coordScreen);

    return TRUE;
}

/*
* cuiPrintText2
*
* Purpose:
*
* Output text to screen on the same line.
*
*/
VOID cuiPrintText2(
    _In_ LPCWSTR lpMessage,
    _In_ WORD wColor)
{
    HANDLE hStd = g_hConsoleOutput;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    WORD savedAttributes = 0;
    BOOL isCarriageReturn = FALSE;
    DWORD written = 0;
    SIZE_T cbLength = 0;

    if (hStd == INVALID_HANDLE_VALUE || !lpMessage || !*lpMessage)
        return;

    if (*lpMessage == L'\r') {
        isCarriageReturn = TRUE;
        lpMessage++;
    }

    if (!GetConsoleScreenBufferInfo(hStd, &csbi))
        return;

    if (wColor) {
        savedAttributes = csbi.wAttributes;
        SetConsoleTextAttribute(hStd, wColor);
    }

    if (isCarriageReturn) {
        COORD pos = { 0, csbi.dwCursorPosition.Y };
        SetConsoleCursorPosition(hStd, pos);

        SIZE_T len = csbi.dwSize.X;
        if (len > (MAXDWORD / sizeof(WCHAR)) - 1)
            len = (MAXDWORD / sizeof(WCHAR)) - 1;

        SIZE_T allocSize = (len + 1) * sizeof(WCHAR);

        WCHAR* spaces = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocSize);
        if (spaces) {
            RtlFillMemory(spaces, len * sizeof(WCHAR), 0x20);
            spaces[len] = L'\0';
            WriteConsole(hStd, spaces, (DWORD)len, &written, NULL);
            SetConsoleCursorPosition(hStd, pos);

            HeapFree(GetProcessHeap(), 0, spaces);
        }
    }

    if (SUCCEEDED(StringCbLength(lpMessage, MAX_PATH * sizeof(WCHAR) * 4, &cbLength))) {
        WriteConsole(hStd, lpMessage, (DWORD)(cbLength / sizeof(WCHAR)), &written, NULL);
    }

    if (wColor)
        SetConsoleTextAttribute(hStd, savedAttributes);
}

/*
* cuiPrintText
*
* Purpose:
*
* Output text to screen.
*
*/
VOID cuiPrintText(
    _In_ LPCWSTR lpMessage,
    _In_ WORD wColor)
{
    HANDLE hStd = g_hConsoleOutput;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    WORD savedAttributes = 0;
    DWORD written;

    if (hStd == INVALID_HANDLE_VALUE || !lpMessage || !*lpMessage)
        return;

    if (wColor) {
        GetConsoleScreenBufferInfo(hStd, &csbi);
        savedAttributes = csbi.wAttributes;
        SetConsoleTextAttribute(hStd, wColor);
    }

    WriteConsole(hStd, lpMessage, (DWORD)wcslen(lpMessage), &written, NULL);
    WriteConsole(hStd, L"\r\n", 2, &written, NULL);

    if (wColor)
        SetConsoleTextAttribute(hStd, savedAttributes);
}
