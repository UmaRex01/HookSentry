#include "SummaryTable.h"
#include <stdio.h>

void InitSummaryTable(LPSUMMARY_TABLE lpSummaryTable)
{
	lpSummaryTable->Rows = NULL;
	lpSummaryTable->RowsCount = 0;
}

void FreeSummaryTable(LPSUMMARY_TABLE lpSummaryTable)
{
	if (lpSummaryTable->Rows == NULL)
		return;

	for (DWORD i = 0; i < lpSummaryTable->RowsCount; i++)
	{
		LPSUMMARY_TABLE_ROW row = &lpSummaryTable->Rows[i];
		for (DWORD j = 0; j < row->DllsCount; j++)
			free(row->DllInfos[j].DllFullPath);
		free(row->DllInfos);
	}

	free(lpSummaryTable->Rows);
	lpSummaryTable->Rows = NULL;
	lpSummaryTable->RowsCount = 0;
}

LPSUMMARY_TABLE_ROW AddSummaryTableRow(LPSUMMARY_TABLE lpSummaryTable, DWORD dwPid)
{
	lpSummaryTable->Rows = (LPSUMMARY_TABLE_ROW)realloc(lpSummaryTable->Rows, (lpSummaryTable->RowsCount + 1) * sizeof(SUMMARY_TABLE_ROW));
	if (lpSummaryTable->Rows == NULL)
		return NULL;

	LPSUMMARY_TABLE_ROW newRow = &lpSummaryTable->Rows[lpSummaryTable->RowsCount];
	newRow->Pid = dwPid;
	newRow->TotalHooks = 0;
	newRow->DllsCount = 0;
	newRow->DllInfos = NULL;

	lpSummaryTable->RowsCount++;
	return newRow;
}

BOOL AddSummaryTableRowInfo(LPSUMMARY_TABLE_ROW lpSummaryTableRow, PWSTR pszDllFullPath, DWORD dwHooksCount)
{
	lpSummaryTableRow->DllInfos = (LPDLL_INFO)realloc(lpSummaryTableRow->DllInfos, (lpSummaryTableRow->DllsCount + 1) * sizeof(DLL_INFO));
	if (lpSummaryTableRow->DllInfos == NULL)
		return FALSE;

	lpSummaryTableRow->TotalHooks += dwHooksCount;
	LPDLL_INFO newDll = &lpSummaryTableRow->DllInfos[lpSummaryTableRow->DllsCount];
	newDll->DllFullPath = pszDllFullPath;
	newDll->HooksCount = dwHooksCount;

	lpSummaryTableRow->DllsCount++;
	return TRUE;
}

void PrintFullTable(LPSUMMARY_TABLE lpSummaryTable, BOOL verbose)
{
	wprintf(L"\n\n*** SUMMARY ***\n\n");
	for (DWORD i = 0; i < lpSummaryTable->RowsCount; i++)
	{
		LPSUMMARY_TABLE_ROW row = &lpSummaryTable->Rows[i];
		wprintf(L"%ws PID: %d has %d hooked functions\n", (row->TotalHooks > 0 ? L"[+]" : L"[-]"), row->Pid, row->TotalHooks);
		if (verbose)
		{
			for (DWORD k = 0; k < row->DllsCount; k++)
			{
				LPDLL_INFO dllInfo = &row->DllInfos[k];
				if (dllInfo->HooksCount == -1)
					wprintf(L"\t%s skipped.\n", dllInfo->DllFullPath);
				else
					wprintf(L"\t%s contains %d hooks\n", dllInfo->DllFullPath, dllInfo->HooksCount);
			}
		}
	}
}
