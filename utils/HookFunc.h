#pragma once
#include "iostream"
#include "windows.h"
#include <vector>
#define RETADDR(old) (DWORD)old + 5
#pragma warning(disable:4996)


struct Registers
{
	DWORD eax;
	DWORD edx;
	DWORD ecx;
	DWORD ebx;
	DWORD edi;
	DWORD esi;
	DWORD ebp;
	DWORD esp;
};

struct MsgBoxArgs
{
	LPARAM cation;
	LPARAM content;

};

typedef struct CrtProcArgs
{
	LPCTSTR lpAppName;
	LPTSTR lpCommandLine;
	LPVOID lpEnvironment;                    // new environment block			
	LPCTSTR lpCurrentDirectory;              // current directory name			
}Proc;



EXTERN_C void CreateProcessM();

HANDLE _declspec(dllexport) WINAPI  HookGetClipboardData(UINT uFormat);
