#include "HookSentry.h"
#include <winternl.h>
#include <stdio.h>

#ifdef _CS_ENABLED
#include "CsUtils.h"
#endif

#pragma comment(lib, "ntdll")

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

BOOL SearchHooks(HANDLE hProcess, LPSUMMARY_TABLE table, BOOL verbose, BOOL printDisass)
{
	PEB peb;
	PEB_LDR_DATA ldr;
	LDR_DATA_TABLE_ENTRY ldrEntry;
	PROCESS_BASIC_INFORMATION processBasicInformation;

	/*
	* Gets basic information about the specified process.We use this to get the PEB base address.
	* Query '0' means ProcessBasicInformation.
	*
	* https://learn.microsoft.com/it-it/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
	*/
	if (NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), 0) != 0)
		return FALSE;

	/*
	* Reads PEB.
	*
	* https://learn.microsoft.com/it-it/windows/win32/api/winternl/ns-winternl-peb
	*/
	if (!ReadProcessMemory(hProcess, processBasicInformation.PebBaseAddress, &peb, sizeof(PEB), NULL))
		return FALSE;

	/*
	* PEB contains the address of LDR, which is a table containing information about
	* the the modules loaded for the process.
	*
	* https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
	*/
	if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL))
		return FALSE;

	/*
	* _PEB_LDR_DATA is not fully documented by Microsoft. However, we know that
	* at offset 0x10 we find _LIST_ENTRY InLoadOrderModuleList which is "a doubly
	* linked list containing pointers to LDR_MODULE strucuture for previous and next
	* module in load order" (http://undocumented.ntinternals.net/).
	*
	* With ldr.Reserved2[1] we point to the first element of this list.
	*
	* https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
	*/
	if (!ReadProcessMemory(hProcess, ldr.Reserved2[1], &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
		return FALSE;

	/*
	* We are saving the first address of the list because, since this is a circular list, we know to
	* have reached the end when we find it again.
	*/
	PVOID pFirstAddress = ldrEntry.Reserved1[0];

	/*
	* Start iterating through the modules in the InLoadOrderModuleList.
	*/
	while (1)
	{
		/*
		* Reserved1 is a pointers to _LIST_ENTRY InLoadOrderLinks which holds pointers to
		* the previous and next module in load order. We do this to move to next module in the list.
		*/
		if (!ReadProcessMemory(hProcess, (PLDR_DATA_TABLE_ENTRY)ldrEntry.Reserved1[0], &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
			return FALSE;

		if (pFirstAddress == ldrEntry.Reserved1[0])
			break;

		/*
		* Doing some acrobatics to read the DLL name stored as it is stored as _UNICODE_STRING.
		* Then we are going to make an infallible test to determine if we are examining a system
		* library or not
		*/
		PWSTR dllName = (PWSTR)malloc(ldrEntry.FullDllName.MaximumLength);
		if (dllName == NULL)
			return FALSE;
		if (!ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, dllName, ldrEntry.FullDllName.MaximumLength, NULL))
			return FALSE;
		if (_wcsnicmp(dllName, SYSTEM_DLL_PATH, wcslen(SYSTEM_DLL_PATH)) != 0)
		{
			print_verbose(verbose, L"[*] %lS not a system library. skipped.\n", dllName);
			free(dllName);
			continue;
		}
		wprintf(L"[*] Working on: %lS\n", dllName);

		/*
		* The next instructions are to open the DLL file on the disk with name = 'dllName'
		* and store its content in a memory buffer that is pointed to by
		* the variable 'pDllImageBase'.
		*/
		HANDLE hFile = CreateFileW(dllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			print_verbose(verbose, L"[!] Failed to open file: %ws. Error: %lu\n", dllName, GetLastError());
			free(dllName);
			continue; // Skip this DLL and move to the next one
		}
		DWORD dwFileLen = GetFileSize(hFile, NULL);
		if (dwFileLen == INVALID_FILE_SIZE)
		{
			print_verbose(verbose, L"[!] Failed to get file size: %ws. Error: %lu\n", dllName, GetLastError());
			free(dllName);
			CloseHandle(hFile);
			continue;  // Skip this DLL and move to the next one
		}
		PVOID pDllImageBase = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);
		if (pDllImageBase == NULL)
		{
			print_verbose(verbose, L"[!] FATAL ERROR. Out of memory\n");
			free(dllName);
			CloseHandle(hFile);
			return FALSE;
		}
		DWORD dwNumberOfBytesRead;
		if (!ReadFile(hFile, pDllImageBase, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead)
		{
			print_verbose(verbose, L"[!] Failed to read file %ws. Error: %lu\n", dllName, GetLastError());
			free(dllName);
			CloseHandle(hFile);
			HeapFree(GetProcessHeap(), NULL, pDllImageBase);
			return FALSE;
		}
		CloseHandle(hFile);

		/*
		* We now read through PE32+ headers.
		* Our goal is the export directory, which contains the names of functions
		* and their offsets.
		*/

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

		/*
		*  Finally, we can go through all the functions in the export directory and look for those damn hooks!
		*/
		DWORD hookCount = 0;
		while (numberOfNames > 0)
		{
			PCHAR functionName = RVA2VA(PCHAR, pDllImageBase, RvaToFileOffset(ntHeader, iNames[numberOfNames - 1]));
			DWORD vaFunctionAddress = iFunctions[iOrdinals[numberOfNames - 1]];

			/*
			* mFunctionAddress holds the address of the function that belongs to the in-memory module that has been loaded by hProcess.
			* iFunctionAddress holds the address of the function that belongs to the DLL that has been read from disk.
			*/
			PVOID mFunctionAddress = RVA2VA(PVOID, ldrEntry.DllBase, vaFunctionAddress);
			PVOID iFunctionAddress = RVA2VA(PVOID, pDllImageBase, RvaToFileOffset(ntHeader, vaFunctionAddress));

			BYTE mFunctionContent[15];
			if (!ReadProcessMemory(hProcess, mFunctionAddress, mFunctionContent, 15, NULL)) {
				continue;
			}

			/*
			* FIRST CHECK - functions should be exactly the same.
			*/
			if (memcmp(mFunctionContent, iFunctionAddress, 15) != 0) // 15 byte max instruction length
			{
				/*
				* SECOND CHECK - is there a jmp as first instruction in the in-memory module function?
				*/
				if (*(BYTE*)mFunctionContent != 0xE9) { // 'jmp' - no jmp, no hook!
					numberOfNames--;
					continue;
				}
				printf("\t[+] Function %s HOOKED!\n", functionName);
				hookCount++;
#ifdef _CS_ENABLED
				if (printDisass)
				{
					wprintf(L"\n\t\tFunction in memory:\n\n");
					PrintDisasm(mFunctionAddress, 15, vaFunctionAddress);
					wprintf(L"\n\t\tFunction on disk:\n\n");
					PrintDisasm(iFunctionAddress, 15, vaFunctionAddress);
					wprintf(L"\n");
				}
#endif
			}
			numberOfNames--;
		}

		if (table != NULL && verbose && hookCount > 0) {
			LPSUMMARY_TABLE_ROW row = AddSummaryTableRow(table, GetProcessId(hProcess));
			if (row == NULL) {
				wprintf(L"[!!!] out of memory\n");
				exit(1);
			}
			if (!AddSummaryTableRowInfo(row, dllName, hookCount)) {
				wprintf(L"[!!!] out of memory\n");
				exit(1);
			}
		}

		free(dllName);
		HeapFree(GetProcessHeap(), NULL, pDllImageBase);
	}

	return TRUE;
}