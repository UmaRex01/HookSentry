#include "SummaryTable.h"
#include "CsUtils.h"
#include <windows.h>
#include <winternl.h>
#include <wchar.h>
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "psapi")

#define SYSTEM_DLL_PATH L"c:\\windows\\system32"
#define RVA2VA(TYPE, BASE, RVA) (TYPE)((ULONG_PTR)BASE + RVA)

#define print_verbose(verbose, ...) \
	do { \
		if(verbose) { \
			wprintf(__VA_ARGS__); \
		} \
	} while(0) \

static DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		DWORD sectionSize = sectionHeader->Misc.VirtualSize;
		DWORD sectionAddress = sectionHeader->VirtualAddress;
		if (rva >= sectionAddress && rva < sectionAddress + sectionSize)
			return rva - sectionAddress + sectionHeader->PointerToRawData;
	}
	return 0;
}

// Reads the loader data from the process memor
static void ReadLdrData(PPEB peb, HANDLE remoteProcess, PEB_LDR_DATA* ldr)
{
	if (remoteProcess != NULL)
		ReadProcessMemory(remoteProcess, peb->Ldr, ldr, sizeof(PEB_LDR_DATA), NULL);
	else
		*ldr = *(PEB_LDR_DATA*)(peb->Ldr);
}

// Reads a loader entry from the process memory
static void ReadLdrEntry(HANDLE remoteProcess, PEB_LDR_DATA ldr, LDR_DATA_TABLE_ENTRY* ldrEntry)
{
	if (remoteProcess != NULL)
		ReadProcessMemory(remoteProcess, ldr.Reserved2[1], ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
	else
		*ldrEntry = *(PLDR_DATA_TABLE_ENTRY)(ldr.Reserved2[1]);
}

// Retrieves the name of the DLL from the loader entry
static PWSTR GetDllName(HANDLE remoteProcess, LDR_DATA_TABLE_ENTRY ldrEntry)
{
	PWSTR dllName = (PWSTR)malloc(ldrEntry.FullDllName.MaximumLength);
	if (dllName == NULL)
	{
		wprintf(L"[!] out of memory\n");
		exit(1);
	}

	if (remoteProcess != NULL)
		ReadProcessMemory(remoteProcess, ldrEntry.FullDllName.Buffer, dllName, ldrEntry.FullDllName.MaximumLength, NULL);
	else
		memcpy_s(dllName, ldrEntry.FullDllName.MaximumLength, ldrEntry.FullDllName.Buffer, ldrEntry.FullDllName.MaximumLength);

	return dllName;
}

// Reads the DLL image base from the file
static PVOID ReadDllImageBase(HANDLE hFile, DWORD dwFileLen)
{
	PVOID pDllImageBase = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);
	if (pDllImageBase == NULL)
	{
		wprintf(L"[!] out of memory\n");
		exit(1);
	}
	DWORD dwNumberOfBytesRead;
	if (!ReadFile(hFile, pDllImageBase, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead)
	{
		wprintf(L"[!] Error reading file. Error: %lu\n", GetLastError());
		HeapFree(GetProcessHeap(), NULL, pDllImageBase);
		return NULL;
	}
	return pDllImageBase;
}

// Searches for hooks in the loaded DLLs
static void SearchHooks(PPEB peb, HANDLE remoteProcess, LPSUMMARY_TABLE_ROW tableRow, BOOL verbose, BOOL printDisass)
{
	PEB_LDR_DATA ldr;
	ReadLdrData(peb, remoteProcess, &ldr);

	LDR_DATA_TABLE_ENTRY ldrEntry;
	ReadLdrEntry(remoteProcess, ldr, &ldrEntry);

	for (;;)
	{
		if (remoteProcess != NULL)
			ReadProcessMemory(remoteProcess, (PLDR_DATA_TABLE_ENTRY)ldrEntry.Reserved1[0], &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
		else
			ldrEntry = *(PLDR_DATA_TABLE_ENTRY)(ldrEntry.Reserved1[0]);

		if (ldrEntry.DllBase == NULL)
			break;

		PWSTR dllName = GetDllName(remoteProcess, ldrEntry);

		if (_wcsnicmp(dllName, SYSTEM_DLL_PATH, wcslen(SYSTEM_DLL_PATH)) != 0)
		{
			print_verbose(verbose, L"[*] %s not a system library. skipped.\n", dllName);
			free(dllName);
			continue;
		}

		HANDLE hFile = CreateFileW(dllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[!] (PID: %d) Failed to open file: %ws. Error: %lu\n", tableRow->Pid, dllName, GetLastError());
			free(dllName);
			continue;
		}
		DWORD dwFileLen = GetFileSize(hFile, NULL);
		if (dwFileLen == INVALID_FILE_SIZE)
		{
			wprintf(L"[!] (PID: %d) Failed to get file size: %ws. Error: %lu\n", tableRow->Pid, dllName, GetLastError());
			free(dllName);
			CloseHandle(hFile);
			continue;  // Skip this DLL and move to the next one
		}
		PVOID pDllImageBase = ReadDllImageBase(hFile, dwFileLen);
		if (pDllImageBase == NULL)
		{
			wprintf(L"[!] (PID: %d) Failed to read file %ws. Error: %lu\n", tableRow->Pid, dllName, GetLastError());
			free(dllName);
			CloseHandle(hFile);
			continue;
		}
		CloseHandle(hFile);

		// DOS Header
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pDllImageBase;
		// NT Header
		PIMAGE_NT_HEADERS ntHeader = RVA2VA(PIMAGE_NT_HEADERS, pDllImageBase, dosHeader->e_lfanew);
		// Data Directory
		PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory;
		// Export Table
		DWORD exportTableVA = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		// Export Directory
		PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, pDllImageBase, RvaToFileOffset(ntHeader, exportTableVA));

		// Read number of names
		DWORD numberOfNames = exportDirectory->NumberOfNames;
		// Get Functions addresses array
		PDWORD iFunctions = RVA2VA(PDWORD, pDllImageBase, RvaToFileOffset(ntHeader, exportDirectory->AddressOfFunctions));
		// Get Function names array
		PDWORD iNames = RVA2VA(PDWORD, pDllImageBase, RvaToFileOffset(ntHeader, exportDirectory->AddressOfNames));
		// Get Function ordinals array
		PWORD iOrdinals = RVA2VA(PWORD, pDllImageBase, RvaToFileOffset(ntHeader, exportDirectory->AddressOfNameOrdinals));

		print_verbose(verbose, L"[*] Working on: %s\n", dllName);

		DWORD hookCount = 0;
		while (numberOfNames > 0)
		{
			PCHAR functionName = RVA2VA(PCHAR, pDllImageBase, RvaToFileOffset(ntHeader, iNames[numberOfNames - 1]));
			DWORD vaFunctionAddress = iFunctions[iOrdinals[numberOfNames - 1]];

			PVOID mFunctionAddress = RVA2VA(PVOID, ldrEntry.DllBase, vaFunctionAddress);
			if (remoteProcess != NULL) {
				BYTE mFunctionContent[15];
				ReadProcessMemory(remoteProcess, mFunctionAddress, mFunctionContent, 15, NULL);
				mFunctionAddress = mFunctionContent;
			}

			if (*(BYTE*)mFunctionAddress != 0xE9) { // 'jmp' - no jmp, no hook!
				numberOfNames--;
				continue;
			}

			PVOID iFunctionAddress = RVA2VA(PVOID, pDllImageBase, RvaToFileOffset(ntHeader, vaFunctionAddress));

			if (memcmp(mFunctionAddress, iFunctionAddress, 15) != 0) // 15 byte max instruction length
			{
				hookCount++;
				if (printDisass)
				{
					printf("\t[+] Function %s HOOKED!\n\n", functionName);
					wprintf(L"\t\tFunction in memory:\n\n");
					PrintDisasm(mFunctionAddress, 15, vaFunctionAddress);
					wprintf(L"\n\t\tFunction on disk:\n\n");
					PrintDisasm(iFunctionAddress, 15, vaFunctionAddress);
					wprintf(L"\n");
				}
			}

			numberOfNames--;
		}

		if (hookCount > 0) {
			if (!AddSummaryTableRowInfo(tableRow, dllName, hookCount)) {
				wprintf(L"[!!!] out of memory\n");
				exit(1);
			}
		}

		HeapFree(GetProcessHeap(), NULL, pDllImageBase);
	}
}

static void SearchHooksInPIDs(DWORD* pids, SIZE_T pidListSize, LPSUMMARY_TABLE table, BOOL verbose, BOOL printDisass)
{
	HANDLE hProcess;
	PROCESS_BASIC_INFORMATION processBasicInformation;
	PEB peb;

	for (DWORD count = 0; count < pidListSize; count++)
	{
		wprintf(L"---\n[*] Working on process %d of %llu with PID: %d\n", count+1, pidListSize, pids[count]);

		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[count]);
		if (!hProcess) {
			wprintf(L"[-] Handle on process %d not obtained. Error: %lu\n", pids[count], GetLastError());
			continue;
		}

		if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), 0) != 0) {
			wprintf(L"[-] NtQueryInformationProcess call failed.\n");
			CloseHandle(hProcess);
			continue;
		}

		if (!ReadProcessMemory(hProcess, processBasicInformation.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
			wprintf(L"[-] ReadProcessMemory - Error: %lu.\n", GetLastError());
			CloseHandle(hProcess);
			continue;
		}

		LPSUMMARY_TABLE_ROW row = AddSummaryTableRow(table, pids[count]);
		if (row == NULL) {
			wprintf(L"[!!!] out of memory\n");
			exit(1);
		}
		SearchHooks(&peb, hProcess, row, verbose, printDisass);

		CloseHandle(hProcess);
	}
}

static void PrintUsage()
{
	wprintf(L"Usage: HookSentry.exe [-a|-p <PID>|-v]\n");
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
		"                      /\nV0.3 - 2024 - @Umarex\n\n";
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
			int pid = _wtoi(argv[i + 1]);
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
		if (wcscmp(argv[i], L"-d") == 0 || wcscmp(argv[i], L"--disass") == 0)
		{
			disass = TRUE;
		}
	}

	SUMMARY_TABLE table;
	InitSummaryTable(&table);

	if (!fullScan && pid == 0)
	{
		wprintf(L"[*] Selected current process.\n");

		DWORD pids[] = { GetCurrentProcessId() };
		SearchHooksInPIDs(pids, 1, &table, verbose, disass);
	}

	else if (!fullScan && pid > 0)
	{
		DWORD pids[] = { pid };
		SearchHooksInPIDs(pids, 1, &table, verbose, disass);
	}

	else if (fullScan)
	{
		wprintf(L"[*] Full system scan requested (could take a while)\n");

		DWORD processes[1024], cbNeeded, cbProcesses;
		if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
		{
			wprintf(L"[-] Failed to enumerate processes.\n");
			return 1;
		}
		cbProcesses = cbNeeded / sizeof(DWORD);
		wprintf(L"[*] %d active processes found\n", cbProcesses);

		SearchHooksInPIDs(processes, cbProcesses, &table, verbose, disass);
	}

	PrintFullTable(&table, verbose);
	FreeSummaryTable(&table);

	return 0;
}
