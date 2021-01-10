// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "../utils/HandleGateWayServer.cpp"
#include "../utils/HookFunc.cpp"
#include "../utils/pe.cpp"
#include "../utils/hook.cpp"
#include "../utils/process.cpp"
#include "../utils/utils.cpp"
#pragma warning(disable:6387)
BOOL RestoreIAT(LPVOID pImageBuffer);

VOID Start()
{
	//MessageBox(0, L"1", 0, 0);
	AllocConsole();
	FILE* f = NULL;
	freopen_s(&f, "CONOUT$", "w", stdout);

	HandleGatewayServer handleGatewayServer;
	handleGatewayServer.Init();
	printf("管道关闭, 任意键退出,\n");
	//这一句必须在FreeConsole之前 不然窗口都关闭了..崩溃

	//system相当于开了一个进程!!!!!参数是暂停... 
	//system("pause");
	fclose(f);
	FreeConsole();

	return;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	//RestoreIAT(hModule);
	//MessageBox(0, 0, L"没进入Switch", 0);
	//远程线程, 并不需要自己开线程
	//如果模块注入则需要自身开一个线程在dll然后运行
	//自身线程结束时调用 FreeLibraryAndExitThread(hModule, 0);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		Start();
		//这一句仅正常注入时执行...
		//可以加个判断当前是否为正常注入, 如果是则正常退出
		//内存注入不应当执行, 而由客户端进行空间的释放.
		FreeLibraryAndExitThread(hModule, 1);
		break;
	}
	case DLL_THREAD_ATTACH:
		::MessageBox(0, L"以附加线程", 0, 0);
		break;
	case DLL_THREAD_DETACH:
		::MessageBox(0, L"dll线程已结束", 0, 0);
		break;
	case DLL_PROCESS_DETACH:
		MessageBox(0, L"进程结束 脱离", L"进程", 0);
		break;
	}
	return TRUE;
}

BOOL RestoreIAT(LPVOID pImageBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;
	HMODULE hModule = 0;
	DWORD rvaImport = 0;
	DWORD rvaName = 0;
	DWORD rvaOriginalThunk = 0;
	DWORD rvaFirstThunk = 0;
	DWORD originalValue = 0;
	LPVOID pFirstValue = NULL;
	DWORD ordinalOfFunc = 0;
	CHAR* pFuncNameAddr = NULL;
	DWORD oldProtect = 0;
	pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + *((DWORD*)((DWORD)(pImageBuffer)+0x3c)));
	rvaImport = (*(pNtHeaders->OptionalHeader.DataDirectory + 1)).VirtualAddress;
	pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageBuffer + rvaImport);

	//以OriginalFirstThunk为基准找到函数名/序号
	//将新值补充到FirstThunk对应的ThunkValue中
	while (rvaOriginalThunk = *((DWORD*)pImport))
	{
		rvaFirstThunk = *((DWORD*)pImport + 4);
		rvaName = pImport->Name;
		if (!(hModule = ::LoadLibraryA((CHAR*)(DWORD)pImageBuffer + rvaName)))
		{
			//这一句不能加, printf 的dll可能没加载导致程序异常退出.
			//printf("加载dll失败 LastError: %d", GetLastError());
			return FALSE;
		}
		//printf("DLL's name: %s\n", (char*)((DWORD)pImageBuffer + rvaName));
		while (originalValue = *(DWORD*)((DWORD)pImageBuffer + (DWORD)rvaOriginalThunk))
		{
			pFirstValue = (LPVOID)((DWORD)pImageBuffer + rvaFirstThunk);
			VirtualProtect(pFirstValue, 4, PAGE_READWRITE, &oldProtect);
			if ((originalValue & 0x80000000) == 0x80000000)
			{
				ordinalOfFunc = (originalValue & 0x7FFFFFFF);
				*(DWORD*)pFirstValue = (DWORD)GetProcAddress(hModule, MAKEINTRESOURCEA(ordinalOfFunc));
			}
			else
			{
				//data 为地址或名称取决于表类型
				pFuncNameAddr = (CHAR*)((DWORD)pImageBuffer + originalValue + 2);
				*(DWORD*)pFirstValue = (DWORD)GetProcAddress(hModule, pFuncNameAddr);
			}
			rvaOriginalThunk += 4;
		}
		pImport++;
	}
	return TRUE;
}