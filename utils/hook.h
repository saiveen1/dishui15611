#pragma once
#include "process.h"

#define __JMP


class _declspec(dllexport) hook
{
public:


public:
	static BOOL IATHOOK(LPVOID module, LPVOID pOldFuncAddr, LPVOID pNewFuncAddr);

	static BOOL IATHOOK(LPVOID module, LPSTR funcName, LPVOID pNewFuncAddr);

	static __JMP BOOL InlineHook(LPVOID pOldFuncAddr,LPVOID pHookFunc, BYTE* pOldBytes);

	static BOOL UnInlineHook(LPVOID pOldFuncAddr, BYTE* pOldBytes);
	
	
};

