#include "hook.h"


BOOL hook::IATHOOK(LPVOID module, LPVOID pOldFuncAddr, LPVOID pNewFuncAddr)
{
	LPVOID pOldOffset = NULL;
	DWORD* funcAddr = NULL;
	pOldOffset = Pe::GetFirstThunkRVA(module, (DWORD)pOldFuncAddr);
	if (!pOldFuncAddr)
		return FALSE;

	funcAddr = ((DWORD*)((DWORD)module + (DWORD)pOldOffset));

	DWORD status = Process::VirProtect(funcAddr, 4, PAGE_READWRITE);
	if (!status) {
		printf("VirtualProtectEx failed. LastError: %d\n",status);
		return FALSE;
	}
	//执行的不应该是E9, E9是JMP应该是线程地址基址 + 函数偏移
	memcpy(funcAddr, &pNewFuncAddr, 4);
	//*funcAddr = (DWORD)pNewFuncAddr;
	return TRUE;
}


//BOOL hook::IATHOOK(LPVOID module, LPSTR funcName, LPVOID pNewFuncAddr)
//{
//	LPVOID pOldOffset = NULL;
//	DWORD* funcAddr = NULL;
//	pOldOffset = Pe::GetFirstThunkRVA(module, (DWORD)pOldFuncAddr);
//	if (!pOldFuncAddr)
//		return FALSE;
//
//	funcAddr = ((DWORD*)((DWORD)module + (DWORD)pOldOffset));
//
//	DWORD status = Process::VirProtect(funcAddr, 4, PAGE_READWRITE);
//	if (!status) {
//		printf("VirtualProtectEx failed. LastError: %d\n", status);
//		return FALSE;
//	}
//	//执行的不应该是E9, E9是JMP应该是线程地址基址 + 函数偏移
//	memcpy(funcAddr, &pNewFuncAddr, 4);
//	//*funcAddr = (DWORD)pNewFuncAddr;
//	return TRUE;
//}

__JMP BOOL hook::InlineHook(LPVOID pOldFuncAddr, LPVOID pHookFunc, BYTE* pOldBytes)
{
	//不能在这个里面用给pOldBytes申请空间..局部作用域 或者用二级指针传值 和普通的一样
	BYTE* hookAddr = (BYTE*)pOldFuncAddr;
	DWORD e9Bytes = 0;
	DWORD jmp = 0xe9;
	Process::VirProtect(pOldBytes, 5, PAGE_READWRITE);
	memcpy(pOldBytes, pOldFuncAddr, 5);

	//这里是代码!!!!必须可执行
	e9Bytes = (DWORD)pHookFunc - (DWORD)pOldFuncAddr - 5;
	Process::VirProtect(hookAddr, 5, PAGE_EXECUTE_READWRITE);
	* hookAddr = 0xe9;
	*(DWORD*)(hookAddr + 1) = e9Bytes;

	//Process::WriteCurrentMemory(hookAddr, &jmp, 1);
	//Process::WriteCurrentMemory(hookAddr + 1, &e9Bytes, 4);
	return TRUE;
}

BOOL hook::UnInlineHook(LPVOID pOldFuncAddr, BYTE* pOldBytes)
{
	Process::VirProtect(pOldBytes, 5, PAGE_EXECUTE_READWRITE);
	memcpy(pOldFuncAddr, pOldBytes, 5);
	//Process::WriteCurrentMemory(pOldFuncAddr, pOldBytes, 5);
	return TRUE;
}

