﻿#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>


EXTERN_C DWORD _declspec(dllexport) InjectDll(DWORD pid, WCHAR argv[]);

#pragma pack(push, 1)
struct InjectArgs {
	UINT64 start; // remote shellcode address
	UINT64 hProcess; // handle of process to inject
	UINT64 hThread; // new thread id
};
#pragma pack(pop)
