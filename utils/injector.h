#pragma once
#include "process.h"



class _declspec(dllexport) injector
{
public:
	static LPVOID InjectByRemoteThread(LPWSTR injectProcName, LPWSTR dllName);
	//注入函数需不需要函数自己决定吧, 毕竟只是个demo
	//自身注入 目标进程, 启动函数
	static LPVOID InjectThrowMemory(LPSTR hostName, LPTHREAD_START_ROUTINE parasitic);

	//无模块内存注入dll
	//需要dll自身修复IAT, 并不通用
	static LPVOID MemoryLoadLibrary(LPSTR hostName, LPSTR moduleName);
};

