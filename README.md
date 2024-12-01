# HookSentry
HookSentry is a quick & dirty tool designed to inspect system DLLs loaded into a Windows process.

It checks for potential hooks in system libraries and displays detailed information about any discovered hooks. The tool compares the in-memory image of each DLL to its on-disk version, identifies functions that have been hooked, and prints disassembled code to help analyze the changes.

**The tool is only compatible with x64 systems.**

## Usage
Just run the executable. You only need to enter one thing – the PID (Process ID) of a remote process. If you do, the program will check the hooks in the process that matches the PID you've given it. Otherwise, it'll check the hooks in its own process.

```cmd
C:\Users\user\Desktop>.\HookSentry.exe <PID>
```

## Example
```cmd
C:\Users\user\Desktop>.\HookSentry.exe

|_| _  _ | (~ _  _ _|_ _
| |(_)(_)|<_)(/_| | | |\/
                      /
V0.2 - 2024 - @UmaRex01


WORKING ON: C:\Windows\SYSTEM32\ntdll.dll

        [*] Function ZwWriteVirtualMemory HOOKED!

                Function in memory:

                0x9DC20:        jmp             0x2005a0
                0x9DC25:        int3
                0x9DC26:        int3
                0x9DC27:        int3

                Function on disk:

                0x9DC20:        mov             r10, rcx
                0x9DC23:        mov             eax, 0x3a

        [*] Function ZwWriteFile HOOKED!

                Function in memory:

                0x9D5E0:        jmp             0x201a40
                0x9D5E5:        int3
                0x9D5E6:        int3
                0x9D5E7:        int3

                Function on disk:

                0x9D5E0:        mov             r10, rcx
                0x9D5E3:        mov             eax, 8


...


*** SUMMARY ***

C:\Windows\SYSTEM32\ntdll.dll contains 86 hooks
C:\Windows\System32\KERNEL32.DLL contains 8 hooks
C:\Windows\System32\KERNELBASE.dll contains 45 hooks
C:\Program Files\Bitdefender\Bitdefender Security\bdhkm\dlls_266864023745032704\bdhkm64.dll skipped.
C:\Program Files\Bitdefender\Bitdefender Security\atcuf\dlls_267396668276705800\atcuf64.dll skipped.
C:\Windows\SYSTEM32\apphelp.dll contains 0 hooks
C:\Windows\System32\ucrtbase.dll contains 0 hooks
C:\Windows\SYSTEM32\VCRUNTIME140.dll contains 0 hooks
```