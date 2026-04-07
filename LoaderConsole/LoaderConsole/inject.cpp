#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include "inject.h"
#include "Stream.h"
#include "encrypt.h"

#pragma comment(lib, "ntdll.lib")


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    ULONG StackZeroBits,
    ULONG SizeOfStackCommit,
    ULONG SizeOfStackReserve,
    LPVOID lpBytesBuffer
    );

struct HandleGuard
{
    HANDLE h = NULL;
    explicit HandleGuard(HANDLE handle) : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    operator HANDLE() const { return h; }
    explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};

typedef struct
{
    PBYTE imageBase;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);
} LoaderData;

DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase +
        ((PIMAGE_DOS_HEADER)loaderData->imageBase)->e_lfanew);

    DWORD delta = (DWORD)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
    if (delta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
    {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (reloc->VirtualAddress)
        {
            PWORD info = (PWORD)(reloc + 1);
            int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            for (int i = 0; i < count; i++)
            {
                if ((info[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
                {
                    PDWORD patch = (PDWORD)(loaderData->imageBase + reloc->VirtualAddress + (info[i] & 0xFFF));
                    *patch += delta;
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
        }
    }

    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDir->Characteristics)
        {
            PIMAGE_THUNK_DATA oft = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDir->OriginalFirstThunk);
            PIMAGE_THUNK_DATA ft = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDir->FirstThunk);

            HMODULE mod = loaderData->loadLibraryA((LPCSTR)loaderData->imageBase + importDir->Name);
            if (!mod)
                return LOADER_ERR_IMPORT_MODULE;

            while (oft->u1.AddressOfData)
            {
                LPCSTR funcName;
                if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    funcName = (LPCSTR)(oft->u1.Ordinal & 0xFFFF);
                else
                    funcName = ((PIMAGE_IMPORT_BY_NAME)(loaderData->imageBase + oft->u1.AddressOfData))->Name;

                DWORD func = (DWORD)loaderData->getProcAddress(mod, funcName);
                if (!func)
                    return LOADER_ERR_IMPORT_FUNC;

                ft->u1.Function = func;
                oft++;
                ft++;
            }
            importDir++;
        }
    }

    if (ntHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
            (loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
            ((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);

        loaderData->rtlZeroMemory(loaderData->imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
        loaderData->rtlZeroMemory(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint, 64);

        if (result)
            return LOADER_SUCCESS;
        return LOADER_ERR_ENTRYPOINT;
    }

    return LOADER_ERR_NO_ENTRYPOINT;
}

VOID stub(VOID) {}

static void dbg(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf("  [DBG] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}


static DWORD wait_for_process(const wchar_t* name, DWORD timeout_ms)
{
    DWORD start_time = GetTickCount();
    DWORD pid = 0;

    dbg("Waiting for process '%ls' to start (timeout: %d ms)...", name, timeout_ms);

    while (GetTickCount() - start_time < timeout_ms)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
        {
            Sleep(100);
            continue;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        if (Process32FirstW(snap, &entry))
        {
            do
            {
                if (!_wcsicmp(entry.szExeFile, name))
                {
                    pid = entry.th32ProcessID;
                    dbg("Found process '%ls' with PID: %lu", name, pid);
                    CloseHandle(snap);
                    return pid;
                }
            } while (Process32NextW(snap, &entry));
        }

        CloseHandle(snap);
        Sleep(100);
    }

    dbg("Timeout waiting for process '%ls'", name);
    return 0;
}


static DWORD find_thread_in_process(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD tid = 0;

    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == pid)
            {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return tid;
}


static InjectResult inject_via_ntcreatethreadex(HANDLE process, PBYTE loaderMem, PBYTE entryAddr, PBYTE remoteImage)
{
    dbg("Attempting NtCreateThreadEx injection...");

    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");

    if (!NtCreateThreadEx)
    {
        dbg("FAIL: Could not resolve NtCreateThreadEx");
        return InjectResult::RemoteThreadFailed;
    }

    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES objAttr{};
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        &objAttr,
        process,
        (LPTHREAD_START_ROUTINE)entryAddr,
        loaderMem,
        FALSE, 
        0, 0, 0,
        NULL
    );

    if (status != 0)
    {
        dbg("FAIL: NtCreateThreadEx returned NTSTATUS: 0x%08X", status);
        return InjectResult::RemoteThreadFailed;
    }

    dbg("Thread created via NtCreateThreadEx, handle: 0x%p", hThread);

    
    DWORD wait = WaitForSingleObject(hThread, 30000);
    CloseHandle(hThread);

    if (wait == WAIT_TIMEOUT)
    {
        dbg("FAIL: Thread wait timed out");
        return InjectResult::RemoteThreadTimeout;
    }

    if (wait == WAIT_FAILED)
    {
        dbg("FAIL: WaitForSingleObject failed: %lu", GetLastError());
        return InjectResult::RemoteThreadCrashed;
    }

    return InjectResult::Success;
}


static InjectResult inject_via_apc(HANDLE process, HANDLE hThread, PBYTE loaderMem, PBYTE entryAddr)
{
    dbg("Attempting APC injection...");

    
    if (SuspendThread(hThread) == (DWORD)-1)
    {
        dbg("FAIL: SuspendThread failed: %lu", GetLastError());
        return InjectResult::RemoteThreadFailed;
    }

    
    DWORD apc_result = QueueUserAPC(
        (PAPCFUNC)entryAddr,
        hThread,
        (ULONG_PTR)loaderMem
    );

    if (!apc_result)
    {
        dbg("FAIL: QueueUserAPC failed: %lu", GetLastError());
        ResumeThread(hThread);
        return InjectResult::RemoteThreadFailed;
    }

    dbg("APC queued, resuming thread...");

   
    if (ResumeThread(hThread) == (DWORD)-1)
    {
        dbg("WARNING: ResumeThread failed: %lu", GetLastError());
    }

    Sleep(100);

    dbg("APC injection completed (cannot verify execution without thread exit)");

    return InjectResult::Success;
}

InjectResult __fastcall Inject(const wchar_t* process_name)
{
    dbg("--- Injection Start ---");

    if (!Streaming::binary_mem || Streaming::binary_size == 0)
    {
        dbg("FAIL: No binary in memory");
        return InjectResult::InvalidPE;
    }

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(Streaming::binary_mem);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return InjectResult::InvalidPE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(Streaming::binary_mem + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return InjectResult::InvalidPE;

    dbg("Binary: %zu bytes, %d sections", Streaming::binary_size, nt->FileHeader.NumberOfSections);


    DWORD pid = wait_for_process(process_name, 60000);
    if (pid == 0)
        return InjectResult::ProcessNotFound;

   
    HandleGuard process(OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid));

    if (!process)
    {
        dbg("FAIL: OpenProcess failed: %lu", GetLastError());
        return InjectResult::OpenProcessFailed;
    }

   
    PBYTE remoteImage = static_cast<PBYTE>(VirtualAllocEx(process, NULL,
        nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!remoteImage)
    {
        dbg("FAIL: VirtualAllocEx image failed: %lu", GetLastError());
        return InjectResult::RemoteAllocImageFailed;
    }

    if (!WriteProcessMemory(process, remoteImage, Streaming::binary_mem,
        nt->OptionalHeader.SizeOfHeaders, NULL))
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        return InjectResult::WriteHeadersFailed;
    }

    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(nt + 1);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (sections[i].SizeOfRawData == 0)
            continue;

        if (!WriteProcessMemory(process, remoteImage + sections[i].VirtualAddress,
            Streaming::binary_mem + sections[i].PointerToRawData,
            sections[i].SizeOfRawData, NULL))
        {
            VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
            return InjectResult::WriteSectionFailed;
        }
    }

 
    DWORD loaderCodeSize = (DWORD)((PBYTE)stub - (PBYTE)loadLibrary);
    if (loaderCodeSize > 3800)
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        return InjectResult::LoaderCodeTooLarge;
    }

    PBYTE loaderMem = static_cast<PBYTE>(VirtualAllocEx(process, NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!loaderMem)
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        return InjectResult::RemoteAllocLoaderFailed;
    }

    LoaderData params{};
    params.imageBase = remoteImage;
    params.loadLibraryA = LoadLibraryA;
    params.getProcAddress = GetProcAddress;
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (ntdll)
        params.rtlZeroMemory = reinterpret_cast<VOID(NTAPI*)(PVOID, SIZE_T)>(
            GetProcAddress(ntdll, "RtlZeroMemory"));

    if (!WriteProcessMemory(process, loaderMem, &params, sizeof(LoaderData), NULL) ||
        !WriteProcessMemory(process, loaderMem + sizeof(LoaderData), loadLibrary, loaderCodeSize, NULL))
    {
        VirtualFreeEx(process, loaderMem, 0, MEM_RELEASE);
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        return InjectResult::WriteLoaderDataFailed;
    }

    PBYTE entryAddr = loaderMem + sizeof(LoaderData);

   
    InjectResult result = InjectResult::RemoteThreadFailed;

  
    dbg("Trying NtCreateThreadEx...");
    result = inject_via_ntcreatethreadex(process, loaderMem, entryAddr, remoteImage);

    if (result != InjectResult::Success)
    {
   
        dbg("NtCreateThreadEx failed, trying APC fallback...");

        DWORD tid = find_thread_in_process(pid);
        if (tid)
        {
            HandleGuard hThread(OpenThread(
                THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | SYNCHRONIZE,
                FALSE, tid));

            if (hThread)
            {
                result = inject_via_apc(process, hThread, loaderMem, entryAddr);
            }
            else
            {
                dbg("FAIL: Could not open thread for APC: %lu", GetLastError());
            }
        }
        else
        {
            dbg("FAIL: No thread found for APC");
        }
    }


    if (result == InjectResult::Success)
    {
        VirtualFreeEx(process, loaderMem, 0, MEM_RELEASE);
    }
    else
    {
      
        dbg("Injection failed, leaving memory allocated for debugging");
    }

    Streaming::cleanup();
    dbg("--- Injection End ---");
    return result;
}

const char* inject_result_to_string(InjectResult r)
{
    switch (r)
    {
    case InjectResult::Success:                return "Injection successful";
    case InjectResult::SnapshotFailed:         return "Process snapshot failed";
    case InjectResult::ProcessNotFound:        return "Target process not found";
    case InjectResult::OpenProcessFailed:      return "Failed to open process";
    case InjectResult::InvalidPE:              return "Invalid PE";
    case InjectResult::RemoteAllocImageFailed: return "VirtualAllocEx failed for image";
    case InjectResult::RemoteAllocLoaderFailed: return "VirtualAllocEx failed for loader";
    case InjectResult::WriteHeadersFailed:     return "Failed to write PE headers";
    case InjectResult::WriteSectionFailed:     return "Failed to write PE section";
    case InjectResult::WriteLoaderDataFailed:  return "Failed to write loader data";
    case InjectResult::WriteLoaderCodeFailed:  return "Failed to write loader code";
    case InjectResult::RemoteThreadFailed:     return "Thread creation/APC failed";
    case InjectResult::RemoteThreadTimeout:    return "Remote thread timed out";
    case InjectResult::RemoteThreadCrashed:    return "Remote thread crashed";
    case InjectResult::LoaderCodeTooLarge:     return "Loader shellcode too large";
    default:                                   return "Unknown error";
    }
}

const char* loader_exit_code_to_string(DWORD code)
{
    switch (code)
    {
    case LOADER_SUCCESS:            return "SUCCESS";
    case LOADER_ERR_RELOC_ACCESS:   return "Relocation access violation";
    case LOADER_ERR_IMPORT_MODULE:  return "LoadLibraryA failed";
    case LOADER_ERR_IMPORT_FUNC:    return "GetProcAddress failed";
    case LOADER_ERR_ENTRYPOINT:     return "DllMain returned FALSE";
    case LOADER_ERR_NO_ENTRYPOINT:  return "No entrypoint found";
    case 0xC0000005:                return "ACCESS_VIOLATION";
    case 0xC0000135:                return "DLL_NOT_FOUND";
    case 0xC0000139:                return "ENTRY_POINT_NOT_FOUND";
    case 0:                         return "DllMain rejected";
    default:                        return "Unknown";
    }
}
