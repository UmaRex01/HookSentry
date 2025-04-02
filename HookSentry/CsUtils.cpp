#include "CsUtils.h"
#include <stdio.h>

#ifdef _CS_ENABLED
#include <capstone.h>

#pragma comment(lib, "capstone.lib")

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
#else
void PrintDisasm(PVOID startAddr, SIZE_T size, DWORD64 vaAddr)
{
	printf("\t\t(ERROR: CAPSTONE MODULE NOT ENABLED)\n\n\t\t");
}
#endif