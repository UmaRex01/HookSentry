#pragma once
#include <windows.h>
#include <wchar.h>
#include "SummaryTable.h"

#define SYSTEM_DLL_PATH L"c:\\windows\\system32"
#define RVA2VA(TYPE, BASE, RVA) (TYPE)((ULONG_PTR)BASE + RVA)

#define print_verbose(verbose, ...) \
	do { \
		if(verbose) { \
			wprintf(__VA_ARGS__); \
		} \
	} while(0) \

BOOL SearchHooks(HANDLE hProcess, LPSUMMARY_TABLE table, BOOL verbose, BOOL printDisass);