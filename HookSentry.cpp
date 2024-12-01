#include <windows.h>
#include <winternl.h>
#include <capstone.h>
#include <stdio.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "capstone.lib")

#define MAX_SUMMARY_TABLE_SIZE 1000
#define SYSTEM_DLL_PATH L"c:\\windows\\system32"
#define RVA2VA(TYPE, BASE, RVA) (TYPE)((ULONG_PTR)BASE + RVA)

typedef struct SUMMARY_TABLE {
	PWSTR DllFullPath;
	INT HookCount;
} SUMMARY_TABLE, * PSUMMARY_TABLE;

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

static void PrintDisasm(PVOID startAddr, SIZE_T size, DWORD64 vaAddr)
{
	csh csHandle;
	cs_insn* insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &csHandle) != CS_ERR_OK)
	{
		printf("Capstone initialization failed.\n");
		return;
	}

	count = cs_disasm(csHandle, (BYTE*)startAddr, size, vaAddr, 0, &insn);
	if (count > 0)
	{
		for (size_t j = 0; j < count; j++)
			printf("\t\t0x%llX:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);

		cs_free(insn, count);
	}
	else
	{
		printf("\t\t(ERROR: Failed to disassemble given code!)\n\n\t\t");
		for (int i = 0; i <= size; i++)
			printf("%02X", *((PBYTE)startAddr + i));
		printf("\n");
	}

	cs_close(&csHandle);
}

static void PrintSummaryTable(PSUMMARY_TABLE* table, DWORD count)
{
	printf("*** SUMMARY ***\n\n");
	for (DWORD i = 0; i < count; i++)
	{
		SUMMARY_TABLE row = *table[i];
		if (row.HookCount == -1)
			wprintf(L"%s skipped.\n", row.DllFullPath);
		else
			wprintf(L"%s contains %d hooks\n", row.DllFullPath, row.HookCount);
	}
}

static void ReadLdrData(PPEB peb, HANDLE remoteProcess, PEB_LDR_DATA* ldr)
{
	if (remoteProcess != NULL)
		ReadProcessMemory(remoteProcess, peb->Ldr, ldr, sizeof(PEB_LDR_DATA), NULL);
	else
		*ldr = *(PEB_LDR_DATA*)(peb->Ldr);
}

static void ReadLdrEntry(HANDLE remoteProcess, PEB_LDR_DATA ldr, LDR_DATA_TABLE_ENTRY* ldrEntry)
{
	if (remoteProcess != NULL)
		ReadProcessMemory(remoteProcess, ldr.Reserved2[1], ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
	else
		*ldrEntry = *(PLDR_DATA_TABLE_ENTRY)(ldr.Reserved2[1]);
}

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
		dllName = ldrEntry.FullDllName.Buffer;

	return dllName;
}

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

static void SearchHooks(PPEB peb, HANDLE remoteProcess)
{
	PSUMMARY_TABLE summaryTable[MAX_SUMMARY_TABLE_SIZE];
	DWORD moduleCount = 0;

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

		PSUMMARY_TABLE tableRow = (PSUMMARY_TABLE)malloc(sizeof(SUMMARY_TABLE));
		if (tableRow == NULL)
		{
			wprintf(L"[!] out of memory\n");
			exit(1);
		}
		tableRow->DllFullPath = GetDllName(remoteProcess, ldrEntry);
		tableRow->HookCount = 0;

		summaryTable[moduleCount] = tableRow;
		moduleCount++;

		wprintf(L"WORKING ON: %s\n", tableRow->DllFullPath);
		if (_wcsnicmp(tableRow->DllFullPath, SYSTEM_DLL_PATH, wcslen(SYSTEM_DLL_PATH)) != 0)
		{
			printf("not a system library. skipped.\n\n");
			tableRow->HookCount = -1;
			continue;
		}
		printf("\n");

		HANDLE hFile = CreateFileW(tableRow->DllFullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[!] Failed to open file: %ws. Error: %lu\n", tableRow->DllFullPath, GetLastError());
			continue;
		}
		DWORD dwFileLen = GetFileSize(hFile, NULL);
		if (dwFileLen == INVALID_FILE_SIZE)
		{
			DWORD dwError = GetLastError();
			wprintf(L"[!] Failed to get file size: %ws. Error: %lu\n", tableRow->DllFullPath, dwError);
			CloseHandle(hFile);
			continue;  // Skip this DLL and move to the next one
		}
		PVOID pDllImageBase = ReadDllImageBase(hFile, dwFileLen);
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
				tableRow->HookCount++;
				printf("\t[*] Function %s HOOKED!\n\n", functionName);
				printf("\t\tFunction in memory:\n\n");
				PrintDisasm(mFunctionAddress, 15, vaFunctionAddress);
				printf("\n\t\tFunction on disk:\n\n");
				PrintDisasm(iFunctionAddress, 15, vaFunctionAddress);
				printf("\n");
			}

			numberOfNames--;
		}

		HeapFree(GetProcessHeap(), NULL, pDllImageBase);
		printf("\n\n");
	}

	PrintSummaryTable(summaryTable, moduleCount);
	for (DWORD i = 0; i < moduleCount; i++) {
		free(summaryTable[i]);
	}
}

int main(int argc, char* argv[])
{
	char banner[] = ""
		"\n|_| _  _ | (~ _  _ _|_ _\n"
		"| |(_)(_)|<_)(/_| | | |\\/\n"
		"                      /\nV0.2 - 2024 - @UmaRex01\n\n";
	printf("%s", banner);

	if (argc > 1)
	{
		HANDLE hProcess;
		PROCESS_BASIC_INFORMATION processBasicInformation;
		PEB peb;

		int pid = atoi(argv[1]);
		if (pid == 0) {
			printf("Invalid PID.\n\n");
			return 1;
		}

		printf("[*] Working on process with PID: %d\n\n", pid);

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hProcess) {
			printf("Handle on process %d not obtained. Error: %lu\n\n", pid, GetLastError());
			return 1;
		}

		if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), 0) != 0) {
			printf("NtQueryInformationProcess call failed.\n\n");
			CloseHandle(hProcess);
			return 1;
		}

		if (!ReadProcessMemory(hProcess, processBasicInformation.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
			printf("ReadProcessMemory - Error: %lu.\n\n", GetLastError());
			CloseHandle(hProcess);
			return 1;
		}

		SearchHooks(&peb, hProcess);
		CloseHandle(hProcess);
	}
	else {
		printf("[*] Working on current process.\n\n");
		SearchHooks(NtCurrentTeb()->ProcessEnvironmentBlock, NULL);
	}

	return 0;
}