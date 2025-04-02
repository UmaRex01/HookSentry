#include <Windows.h>
#include <wchar.h>
#include <psapi.h>
#include "SummaryTable.h"
#include "HookSentry.h"

#pragma comment(lib, "psapi")

static void SearchHooksInPIDs(DWORD* pids, SIZE_T pidListSize, BOOL verbose, BOOL printDisass)
{
	SUMMARY_TABLE table;
	if (verbose)
		InitSummaryTable(&table);

		for (DWORD count = 0; count < pidListSize; count++)
		{
			wprintf(L"---\n[*] Working on process %d of %llu with PID: %d\n", count + 1, pidListSize, pids[count]);

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[count]);
			if (!hProcess) {
				wprintf(L"[-] Cannot open an handle on PID: %d  (Low priv?)\n", pids[count]);
				continue;
			}			

			if (!SearchHooks(hProcess, &table, verbose, printDisass))
				wprintf(L"[!] Task failed for process %d. Skipping.\n", pids[count]);

			CloseHandle(hProcess);
		}

		if (verbose) {
			PrintFullTable(&table);
			FreeSummaryTable(&table);
		}
}

static void PrintUsage()
{
	wprintf(L"Usage: HookSentry.exe [-a|-p <PID>|-v|-d]\n");
	wprintf(L"Options:\n");
	wprintf(L"\t-h, --help: Show this message\n");
	wprintf(L"\t-p <PID>, --pid <PID>: Analyze the process with PID <PID>\n");
	wprintf(L"\t-a, --all: Analyze all active processes\n");
	wprintf(L"\t-v, --verbose: Enable verbose output\n");
	wprintf(L"\t-d, --disass: Display disassembled code\n");
}

int wmain(int argc, wchar_t* argv[])
{
	wchar_t banner[] = L""
		"\n|_| _  _ | (~ _  _ _|_ _\n"
		"| |(_)(_)|<_)(/_| | | |\\/\n"
		"                      /\nV0.4 - @Umarex\n\n";
	wprintf(L"%s", banner);

	int pid = 0;
	BOOL verbose = FALSE;
	BOOL disass = FALSE;
	BOOL fullScan = FALSE;

	for (int i = 0; i < argc; i++)
	{
		// -h, --help --> Print Usage
		if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0)
		{
			PrintUsage();
			return 1;
		}

		// -p <PID>, --pid <pid> --> Work on specific PID
		if (wcscmp(argv[i], L"-p") == 0 || wcscmp(argv[i], L"--pid") == 0)
		{
			pid = _wtoi(argv[i + 1]);
			if (pid == 0) {
				wprintf(L"Invalid PID.\n\n");
				PrintUsage();
				return 1;
			}
		}

		// -v, --verbose --> Verbose output
		if (wcscmp(argv[i], L"-v") == 0 || wcscmp(argv[i], L"--verbose") == 0)
		{
			verbose = TRUE;
		}

		// -a, --all --> Works on all active processes
		if (wcscmp(argv[i], L"-a") == 0 || wcscmp(argv[i], L"--all") == 0)
		{
			fullScan = TRUE;
		}

		// -d, --disass --> Print disassembled code
#ifdef _CS_ENABLED
		if (wcscmp(argv[i], L"-d") == 0 || wcscmp(argv[i], L"--disass") == 0)
		{
			disass = TRUE;
		}
#endif
	}

	if (!fullScan && pid == 0)
	{
		wprintf(L"[*] Selected current process.\n");

		DWORD pids[] = { GetCurrentProcessId() };
		SearchHooksInPIDs(pids, 1, verbose, disass);
	}

	else if (!fullScan && pid > 0)
	{
		DWORD pids[] = { pid };
		SearchHooksInPIDs(pids, 1, verbose, disass);
	}

	else if (fullScan)
	{
		wprintf(L"[*] Full system scan requested (could take a while)\n");

		DWORD pids[1024], cbNeeded, cbPids;
		if (!EnumProcesses(pids, sizeof(pids), &cbNeeded))
		{
			wprintf(L"[-] Failed to enumerate processes.\n");
			return 1;
		}
		cbPids = cbNeeded / sizeof(DWORD);
		wprintf(L"[*] %d active processes found\n", cbPids);

		SearchHooksInPIDs(pids, cbPids, verbose, disass);
	}

	return 0;
}
