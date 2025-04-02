#pragma once
#include <windows.h>

typedef struct {
	PWSTR DllFullPath;
	DWORD HooksCount;
} DLL_INFO, * LPDLL_INFO;

typedef struct {
	DWORD Pid;
	DWORD TotalHooks;
	LPDLL_INFO DllInfos;
	DWORD DllsCount;
} SUMMARY_TABLE_ROW, * LPSUMMARY_TABLE_ROW;

typedef struct {
	LPSUMMARY_TABLE_ROW Rows;
	DWORD RowsCount;
} SUMMARY_TABLE, * LPSUMMARY_TABLE;

void InitSummaryTable(LPSUMMARY_TABLE lpSummaryTable);
void FreeSummaryTable(LPSUMMARY_TABLE lpSummaryTable);
LPSUMMARY_TABLE_ROW AddSummaryTableRow(LPSUMMARY_TABLE lpSummaryTable, DWORD dwPid);
BOOL AddSummaryTableRowInfo(LPSUMMARY_TABLE_ROW lpSummaryTableRow, PWSTR pszDllFullPath, DWORD dwHooksCount);
void PrintFullTable(LPSUMMARY_TABLE lpSummaryTable);
