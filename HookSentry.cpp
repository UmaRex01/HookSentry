#include <windows.h>
#include <winternl.h>
#include <capstone.h>
#include <stdio.h>

#define MAX_SUMMARY_TABLE_SIZE 100
#define SYSTEM_DLL_PATH L"c:\\windows\\system32"
#define RVA2VA(TYPE, BASE, RVA) (TYPE)((ULONG_PTR)BASE + RVA)

typedef struct SUMMARY_TABLE {
	UNICODE_STRING DllFullPath;
	INT HookCount;
} SUMMARY_TABLE, * PSUMMARY_TABLE;

DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva)
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

void PrintDisasm(PVOID startAddr, SIZE_T size, DWORD64 vaAddr)
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

void PrintSummaryTable(PSUMMARY_TABLE* table, DWORD count)
{
	printf("*** SUMMARY ***\n\n");
	for (DWORD i = 0; i < count; i++)
	{
		SUMMARY_TABLE row = *table[i];
		if (row.HookCount == -1)
			wprintf(L"%s skipped.\n", row.DllFullPath.Buffer);
		else
			wprintf(L"%s contains %d hooks\n", row.DllFullPath.Buffer, row.HookCount);
	}
}

int main(int argc, char* argv[])
{
	char banner[] = ""
		"\n|_| _  _ | (~ _  _ _|_ _\n"
		"| |(_)(_)|<_)(/_| | | |\\/\n"
		"                      /\nV0.1 - 2024 - @UmaRex01\n\n\n";
	printf("%s", banner);

	PSUMMARY_TABLE summaryTable[MAX_SUMMARY_TABLE_SIZE];
	DWORD moduleCount = 0;

	PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
	PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)ldr->Reserved2[1]; // skipping base module - this process

	for (ldrEntry = (PLDR_DATA_TABLE_ENTRY)ldrEntry->Reserved1[0]; ldrEntry->DllBase != NULL; ldrEntry = (PLDR_DATA_TABLE_ENTRY)ldrEntry->Reserved1[0])
	{
		PSUMMARY_TABLE tableRow = (PSUMMARY_TABLE)malloc(sizeof(SUMMARY_TABLE));
		tableRow->DllFullPath = ldrEntry->FullDllName;
		tableRow->HookCount = 0;

		summaryTable[moduleCount] = tableRow;
		moduleCount++;

		wprintf(L"WORKING ON: %s\n", ldrEntry->FullDllName.Buffer);
		if (_wcsnicmp(ldrEntry->FullDllName.Buffer, SYSTEM_DLL_PATH, wcslen(SYSTEM_DLL_PATH)) != 0)
		{
			printf("not a system library. skipped.\n\n");
			tableRow->HookCount = -1;
			continue;
		}
		printf("\n");

		HANDLE hFile = CreateFileW(ldrEntry->FullDllName.Buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[!] Failed to open file: %ws. Error: %lu\n", ldrEntry->FullDllName.Buffer, GetLastError());
			continue;
		}
		DWORD dwFileLen = GetFileSize(hFile, NULL);
		if (dwFileLen == INVALID_FILE_SIZE)
		{
			DWORD dwError = GetLastError();
			wprintf(L"[!] Failed to get file size: %ws. Error: %lu\n", ldrEntry->FullDllName.Buffer, dwError);
			CloseHandle(hFile);
			continue;  // Skip this DLL and move to the next one
		}
		PVOID pDllImageBase = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);
		DWORD dwNumberOfBytesRead;
		if (!ReadFile(hFile, pDllImageBase, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead)
		{
			printf("[!] Error reading file: %ws. Error: %lu\n", ldrEntry->FullDllName.Buffer, GetLastError());
			HeapFree(GetProcessHeap(), NULL, pDllImageBase);
			CloseHandle(hFile);
			continue;
		}
		CloseHandle(hFile);

		// DOS Header
		PIMAGE_DOS_HEADER mDosHeader = (PIMAGE_DOS_HEADER)ldrEntry->DllBase;
		PIMAGE_DOS_HEADER iDosHeader = (PIMAGE_DOS_HEADER)pDllImageBase;

		// NT Header
		PIMAGE_NT_HEADERS mNtHeader = RVA2VA(PIMAGE_NT_HEADERS, ldrEntry->DllBase, mDosHeader->e_lfanew);
		PIMAGE_NT_HEADERS iNtHeader = RVA2VA(PIMAGE_NT_HEADERS, pDllImageBase, iDosHeader->e_lfanew);

		// Data Directory
		PIMAGE_DATA_DIRECTORY mDataDirectory = (PIMAGE_DATA_DIRECTORY)mNtHeader->OptionalHeader.DataDirectory;
		PIMAGE_DATA_DIRECTORY iDataDirectory = (PIMAGE_DATA_DIRECTORY)iNtHeader->OptionalHeader.DataDirectory;

		// Export Table
		DWORD exportTableVA = mDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (exportTableVA != iDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			// maybe version mismatch
			printf("[-] unexpected error: EAT VA mismatch\n");
			HeapFree(GetProcessHeap(), NULL, pDllImageBase);
			continue;
		}

		PIMAGE_EXPORT_DIRECTORY mExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, ldrEntry->DllBase, exportTableVA);
		PIMAGE_EXPORT_DIRECTORY iExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, pDllImageBase, RvaToFileOffset(iNtHeader, exportTableVA));

		DWORD numberOfNames = mExportDirectory->NumberOfNames;

		// Functions addresses array
		PDWORD mFunctions = RVA2VA(PDWORD, ldrEntry->DllBase, mExportDirectory->AddressOfFunctions);
		PDWORD iFunctions = RVA2VA(PDWORD, pDllImageBase, RvaToFileOffset(iNtHeader, iExportDirectory->AddressOfFunctions));

		// Function names array
		PDWORD mNames = RVA2VA(PDWORD, ldrEntry->DllBase, mExportDirectory->AddressOfNames);
		PDWORD iNames = RVA2VA(PDWORD, pDllImageBase, RvaToFileOffset(iNtHeader, iExportDirectory->AddressOfNames));

		// Function ordinals array
		PWORD mOrdinals = RVA2VA(PWORD, ldrEntry->DllBase, mExportDirectory->AddressOfNameOrdinals);
		PWORD iOrdinals = RVA2VA(PWORD, pDllImageBase, RvaToFileOffset(iNtHeader, iExportDirectory->AddressOfNameOrdinals));

		do
		{
			PCHAR functionName = RVA2VA(PCHAR, ldrEntry->DllBase, mNames[numberOfNames - 1]);
			if (strcmp(functionName, RVA2VA(PCHAR, pDllImageBase, RvaToFileOffset(iNtHeader, iNames[numberOfNames - 1]))))
			{ // should never happen
				printf("[!] unexpected error: function name mismatch. Skipping %s.\n", functionName);
				continue;
			}

			DWORD vaFunctionAddress = mFunctions[mOrdinals[numberOfNames - 1]];
			if (vaFunctionAddress != iFunctions[iOrdinals[numberOfNames - 1]])
			{// should never happen
				printf("[!] unexpected error: function va address mismatch. Skipping %s.\n", functionName);
				continue;
			}

			PVOID mFunctionAddress = RVA2VA(PVOID, ldrEntry->DllBase, vaFunctionAddress);
			if (*(BYTE*)mFunctionAddress != 0xE9) // 'jmp' - no jmp, no hook!
				continue;

			PVOID iFunctionAddress = RVA2VA(PVOID, pDllImageBase, RvaToFileOffset(iNtHeader, vaFunctionAddress));

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
		} while (--numberOfNames);

		HeapFree(GetProcessHeap(), NULL, pDllImageBase);
		printf("\n\n");
	}

	PrintSummaryTable(summaryTable, moduleCount);
	for (DWORD i = 0; i < moduleCount; i++) {
		free(summaryTable[i]);
	}

	return 0;
}