# HookSentry
HookSentry is a simple tool for inspecting system DLLs loaded into processes, looking for functions hooked from AV/EDR.

It scans for potential hooks in system libraries and provides detailed information about each hook it finds. The tool compares the in-memory image of each DLL with its on-disk version, identifies hooked functions, and prints disassembled code to help analyze the changes.

In addition to scanning a specific process or itself, HookSentry can perform a full scan of all active processes on the system. 

**The tool is compatible with x64 systems only.**

## Usage
```cmd
C:\Users\user\Desktop>.\HookSentry.exe -h

|_| _  _ | (~ _  _ _|_ _
| |(_)(_)|<_)(/_| | | |\/
                      /
V0.4 - @Umarex

Usage: HookSentry.exe [-a|-p <PID>|-v]
Options:
        -h, --help: Show this message
        -p <PID>, --pid <PID>: Analyze the process with PID <PID>
        -a, --all: Analyze all active processes
        -v, --verbose: Enable verbose output
        -d, --disass: Display disassembled code
```

## Example
```cmd
C:\Users\user\Desktop>.\HookSentry.exe -v -d

|_| _  _ | (~ _  _ _|_ _
| |(_)(_)|<_)(/_| | | |\/
                      /
V0.4 - @Umarex

[*] Selected current process.
---
[*] Working on process 1 of 1 with PID: 2120
[*] Working on: C:\Windows\SYSTEM32\ntdll.dll
        [+] Function ZwWriteVirtualMemory HOOKED!

                Function in memory:

                0x9DC20:        jmp             0x2005a0
                0x9DC25:        int3
                0x9DC26:        int3
                0x9DC27:        int3

                Function on disk:

                0x9DC20:        mov             r10, rcx
                0x9DC23:        mov             eax, 0x3a


[...]

[*] C:\Program Files\Bitdefender\Bitdefender Security\bdhkm\dlls_266864023745032704\bdhkm64.dll not a system library. skipped.
[*] C:\Program Files\Bitdefender\Bitdefender Security\atcuf\dlls_267396668276705800\atcuf64.dll not a system library. skipped.
[*] Working on: C:\Windows\System32\ucrtbase.dll
[*] Working on: C:\Windows\SYSTEM32\VCRUNTIME140.dll

*** SUMMARY ***

[+] PID: 2120 has 139 hooked functions
        C:\Windows\SYSTEM32\ntdll.dll contains 86 hooks
        C:\Windows\System32\KERNEL32.DLL contains 8 hooks
        C:\Windows\System32\KERNELBASE.dll contains 45 hooks
```

## Run HookSentry as Beacon Object File (BOF)
It is also possible to run HookSentry as BOF. The **HookSentryBOF** project is a slightly modified version of the original one, which allows to run the tool as BOF with the following limitations:
- cannot perform full system scan
- cannot display disassembled info
- must be run with target PID as mandatory argument

**Please note!** HookSentryBOF has not been fully tested against any C2 framework, but only against the [COFFLoader](https://github.com/trustedsec/COFFLoader) project.
