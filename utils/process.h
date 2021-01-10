#pragma once
#include <windows.h>
#include "iostream"
#include <TlHelp32.h>
#include <winternl.h>
#include "pe.h"
#pragma warning(disable:6387)
#pragma warning(disable:6335)
#define JUNKS \
__asm _emit 0x12 \
__asm _emit 0x34 \
__asm _emit 0x56 \
__asm _emit 0x31 \
__asm _emit 0x13 \
__asm _emit 0x15 \
#define MAX_LENGTH 0x20
// Don't change this!
#define _JUNK_BLOCK(s) __asm jmp s JUNKS __asm s:
//e_lfanew
#define GET_SIZEOFIMAGE_OFFSET(baseAddress) (LPCVOID)(baseAddress + *((DWORD*)((baseAddress) + 0x3c)) + 0x50)

#define GET_NT_HEADERS(baseAddress) (LPVOID)(baseAddress + *((DWORD*)((baseAddress) + 0x3c)))
#pragma comment(lib,"ntdll.lib")
EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
//set Unicode none
class _declspec(dllexport) Process
{
public:
	//�������ƻ�ȡPID
	 static DWORD GetPID(LPWSTR processName);
	 
	 static BOOL GetProcInfo(PROCESS_INFORMATION* pi);
	 
	 static DWORD GetModuleAddr(DWORD PID, LPWSTR moduleName, DWORD* sizeOfModule, CHAR* moduleFullPath);

	 static DWORD GetModuleAddr(LPSTR hostName, LPSTR moduleName);
	 
	 //����ռ�
	 static LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t, DWORD protect);

	 static BOOL VirtualFreeM(DWORD pid, LPVOID lpAddr);
	 
	 //ALL_ACCESS��OpenProcess
	 static HANDLE OpenProcessM(DWORD pid);
	 static HANDLE OpenProcessM(CHAR* procName);
	 static HANDLE OpenProcessM(WCHAR* procName);
	 
	 //�������ƹ��𴴽�����
	 static PROCESS_INFORMATION CreateProcessSuspend(LPSTR processName);
	 
	 //�رվ��
	 static VOID CloseHandles(PROCESS_INFORMATION);
	 
	 //��ȡ�߳�Context
	 static CONTEXT GetThreadContext(HANDLE hThread);
	 
	 //��ȡ������ĳ���̵߳�ImageBase
	 static DWORD GetThreadImageBase(PROCESS_INFORMATION procInfo);
	 
	 //��ȡ������ĳ���̵߳�ImageBuffer
	 static LPVOID GetThreadImageBuffer(PROCESS_INFORMATION procInfo, OUT DWORD* sizeOfImage);
	 
	 
	 static __IMAGEBUFFER BOOL RestoreImageAddrTable(LPVOID pImageBuffer, DWORD hostPID, HANDLE hProcHost);
	 
	 static DWORD VirProtect(LPVOID addr, DWORD dwLength, DWORD flNewProtect);
	 
	 static DWORD WriteCurrentMemory(LPVOID baseAddr, LPVOID buffer, DWORD length);
	 
	 static BOOL EnableDebugPrivileges();
};
