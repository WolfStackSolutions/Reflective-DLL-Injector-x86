#pragma once
#include <Windows.h>

enum class InjectResult : int
{
	Success = 0,
	SnapshotFailed,
	ProcessNotFound,
	OpenProcessFailed,
	InvalidPE,
	RemoteAllocImageFailed,
	RemoteAllocLoaderFailed,
	WriteHeadersFailed,
	WriteSectionFailed,
	WriteLoaderDataFailed,
	WriteLoaderCodeFailed,
	RemoteThreadFailed,
	RemoteThreadTimeout,
	RemoteThreadCrashed,
	LoaderCodeTooLarge
};

#define LOADER_ERR_RELOC_ACCESS    0xDEAD0001
#define LOADER_ERR_IMPORT_MODULE   0xDEAD0002
#define LOADER_ERR_IMPORT_FUNC     0xDEAD0003
#define LOADER_ERR_ENTRYPOINT      0xDEAD0004
#define LOADER_ERR_NO_ENTRYPOINT   0xDEAD0005
#define LOADER_SUCCESS             0x00000001

InjectResult __fastcall Inject(const wchar_t* process_name);
const char* inject_result_to_string(InjectResult result);
const char* loader_exit_code_to_string(DWORD code);
