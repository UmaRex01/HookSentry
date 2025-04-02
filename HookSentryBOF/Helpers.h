#pragma once
#include <windows.h>

#ifdef __cplusplus
#define DFR(module, function) \
	DECLSPEC_IMPORT decltype(function) module##$##function;
#define DFR_LOCAL(module, function) \
	DECLSPEC_IMPORT decltype(function) module##$##function; \
	decltype(module##$##function) * function = module##$##function;
#endif // end of __cplusplus

// -------- NTDLL DEFINITIONS - BEGIN

// https://github.com/winsiderss/systeminformer/blob/06f8fd943b3e05baa42e2fd1f45246caf8d7ff95/phnt/include/phnt_ntdef.h#L68
typedef LONG KPRIORITY, * PKPRIORITY;

// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	//PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	//PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	PVOID                         PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
WINBASEAPI NTSTATUS NtQueryInformationProcess(
	IN HANDLE               ProcessHandle,
	IN DWORD                ProcessInformationClass,
	OUT PVOID               ProcessInformation,
	IN ULONG                ProcessInformationLength,
	OUT PULONG              ReturnLength
);
// -------- NTDLL DEFINITIONS - END
