# DLL-Shellcode-Injector-x86

Downloads encrypted shellcode into memory from a server and maps it into an x86 process without touching the disk. Barebones reflective loader with some extra features added over time.

## Configuration

Edit `Settings.h` before building:
```cpp
namespace Settings
{
    static const std::string server_ip = "1.1.1.1";
    static const uint16_t server_port = 1222;
    static const std::wstring target_process = L"processnamex86";
    static const uint8_t XOR_KEY[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    static const size_t XOR_KEY_SIZE = sizeof(XOR_KEY);
}
```

Change these to your server IP, port, target process name, and XOR key. The key must match whatever your server uses to encrypt.

## What It Does

- Downloads XOR'd DLL bytearray from a server
- Decrypts it and stores in memory buffer
- Waits for you to start the target process (menu option 3 does download + inject auto)
- Injects into x86 process using NtCreateThreadEx with APC fallback
- Erases PE headers after loading
- Erases entrypoint after execution
- Console menu for easy operation

## Requirements

- Needs to be able to get a handle to the process
- Target must be x86 (32-bit), it will check and warn if you try x64
- Uses CRT (C Runtime)
- Windows with ntdll.dll

## Menu Options
```cpp
--- Actions ---
[1] Download DLL from server
[2] Inject into target
[3] Download + Inject (auto)
[0] Exit
```
Option 3 is auto mode, downloads then immediately waits for process and injects. Option 2 assumes you already downloaded the DLL and just want to inject.

## Defense Evasion

This tool attempts some basic evasion techniques but it is **not** fully undetectable.

### What We Try To Do

- **No disk touching** - everything happens in memory, no DLL dropped to disk
- **XOR encryption** - traffic is encrypted with XOR (key is hardcoded so not great)
- **PE header erasure** - after loading we zero out the headers so memory scanners see less
- **Entrypoint erasure** - first 64 bytes of code get wiped after execution
- **NtCreateThreadEx** - uses native API instead of CreateRemoteThread to bypass some hooks
- **APC fallback** - if thread creation fails it tries APC injection as backup

### What We Don't Do (And Why It Gets Caught)

The scanner output below shows real detections from a basic security product. This tool does **not** evade these:
```cpp
[ VIRTUAL ADDRESS DESCRIPTOR SCAN ]
19:09:56 [DETECT] [VAD] Executable private region @ 0x2fde0000 size=0x51000 protect=0x40
19:09:56 [RESULT] VAD Region Scan: 1 detection(s) / 2776 checked
[ THREAD START ADDRESS SCAN ]
19:09:56 [DETECT] [THREAD] Thread 59408 start @ 0x2fde1770 is outside all known modules
19:09:56 [RESULT] Thread Start Addresses: 1 detection(s) / 66 checked
```
**VAD scan detection** - We allocate RWX (Read-Write-Execute) memory with VirtualAllocEx. This is suspicious because normal code doesn't need writable and executable memory at the same time. The VAD tree tracks this and scanners flag it immediately. We could try RW first then flip to RX but that creates more suspicious API calls.

**Thread start address detection** - Our thread starts at `0x2fde1770` which is inside our allocated memory block (`0x2fde0000`) but outside any known loaded module. Legitimate threads start inside kernel32.dll, ntdll.dll, or the main EXE. A thread starting in unattributed memory is an instant red flag. This is the biggest detection vector and hard to fix without complex module stomping or thread hijacking.

```cpp
[ HANDLE AUDIT ]
19:09:51 [ WARN ] [INT-MODULE] Module loaded: KERNEL32.dll @ 0x75C20000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: USER32.dll @ 0x762A0000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: D3DCOMPILER_43.dll @ 0x68330000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-core-synch-l1-2-0 @ 0x75450000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-core-fibers-l1-1-1 @ 0x75450000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: MSVCP140.dll @ 0x70E30000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: IMM32.dll @ 0x75E00000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: VCRUNTIME140.dll @ 0x70EA0000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-crt-heap-l1-1-0.dll @ 0x76BE0000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-crt-stdio-l1-1-0.dll @ 0x76BE0000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-crt-string-l1-1-0.dll @ 0x76BE0000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-crt-utility-l1-1-0.dll @ 0x76BE0000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-crt-convert-l1-1-0.dll @ 0x76BE0000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-crt-runtime-l1-1-0.dll @ 0x76BE0000
19:09:51 [ WARN ] [INT-MODULE] Module loaded: api-ms-win-crt-math-l1-1-0.dll @ 0x76BE0000
```
These are just normal DLL loads so not really a detection, but the audit log shows the injector loading modules which creates a footprint.

### Other Things That Will Get You Caught

- **No control flow obfuscation** - the loader shellcode is straight line execution, easy to signature
- **No API hashing** - we use plain GetProcAddress with string literals
- **Static imports** - we import from kernel32, user32, etc normally instead of dynamic resolution
- **Console window** - we AllocConsole which is obvious
- **Network traffic** - plain TCP socket to download, not HTTPS or DNS tunneling
- **Process open** - we still need PROCESS_VM_OPERATION and friends which is logged by EDR

## Architecture

The reflective loader works by:

1. Mapping the DLL sections into remote process manually (not using LoadLibrary)
2. Fixing up relocations if loaded at a different base
3. Walking the import table and resolving functions
4. Calling DllMain with DLL_PROCESS_ATTACH
5. Zeroing evidence

The shellcode that does this is position independent and gets copied into the target along with a small data structure containing function pointers (LoadLibraryA, GetProcAddress, RtlZeroMemory).

## Build Notes

Compile as **x86 (Win32)** not x64. The target process must also be x86. If you try to inject x64 code into an x86 process it will crash immediately and the debug log will show `x64 - WRONG ARCH` in the machine field.

Debug output goes to console. You can see exactly what it's doing including section names, addresses, relocation delta, etc. Useful for troubleshooting but obviously noisy.

## Disclaimer

This is for educational purposes and authorized testing only. The detection rate is high, don't use this for anything serious without major modifications. The scan results above prove that out of the box it gets caught by basic memory scanning.
