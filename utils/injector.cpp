#include "injector.h"
#pragma warning(disable:6001)
VOID RebaseRelocation(LPVOID pImageBuffer, DWORD dwNewImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBuffer + \
		pOptionHeader->DataDirectory[5].VirtualAddress);
	DWORD dwImageBaseDelta = dwNewImageBase - pOptionHeader->ImageBase; // 新旧ImageBase 的差值	
	if (!pOptionHeader->DataDirectory[5].VirtualAddress)
	{
		pOptionHeader->ImageBase = dwImageBaseDelta;
		return;
	}
	// 重定位表的 VirtualAddress + 低12位偏移 = RVA
	// RVA + ImageBase 这个内存里存储了一个“指针”
	// 要修改的是这个“指针”的值，要让这个“指针”加上两个ImageBase的差值
	while (pRelocationTable->VirtualAddress || pRelocationTable->SizeOfBlock)
	{
		size_t n = (pRelocationTable->SizeOfBlock - 8) / 2; // 可能需要修改的地址数量（高4位==0011才要修改）
		PWORD pOffset = (PWORD)((DWORD)pRelocationTable + 8); // 2字节偏移的数组
		for (size_t i = 0; i < n; i++)
		{
			// 高4位等于0011才需要重定位
			if ((pOffset[i] & 0xF000) == 0x3000)
			{
				// 计算需要重定位的数据的RVA地址
				DWORD dwRva = pRelocationTable->VirtualAddress + (pOffset[i] & 0x0FFF);
				// 计算在镜像中的地址
				PDWORD pData = (PDWORD)((DWORD)pImageBuffer + dwRva);
				// 重定位，即修正写死的地址				
				*pData += dwImageBaseDelta;
			}
		}
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	// 修改 ImageBase
	pOptionHeader->ImageBase = dwNewImageBase;
}



/// <summary>
/// 在线程A中开远程线程, 因为loadlibrary的调用格式和线程回调一样所以
/// 可以直接将其当做线程函数使用, 因为是user32所以地址都一样
/// 其中的dll名称需要在线程A中申请空间, 然后调用
/// </summary>
/// <param name="processName"></param>
/// <param name="dllName"></param>
/// <returns>注入dll的baseAddress</returns>
LPVOID injector::InjectByRemoteThread(LPWSTR injectProcName, LPWSTR dllName)
{

	HANDLE hProcess = 0;
	HANDLE hRemoteThread = 0;
	LPVOID dllNameAdrress = NULL;
	DWORD dllBaseAddress = NULL;
	TCHAR dllFullPath[MAX_PATH];
	//dll 一定要获取完整路径, 因为在A进程中是找不到该dll的
	::GetFullPathName(dllName, MAX_PATH, dllFullPath, NULL);
	hProcess = Process::OpenProcessM(injectProcName);
	//在进程中申请空间给dll名字, 当做参数, 随意分配空间即可
	dllNameAdrress = Process::VirtualAllocate(hProcess, NULL, wcslen(dllFullPath), PAGE_EXECUTE_READWRITE);
	::WriteProcessMemory(hProcess, dllNameAdrress, dllName, wcslen(dllFullPath), NULL);
	hRemoteThread = ::CreateRemoteThread(
		hProcess,
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)LoadLibraryW,
		dllNameAdrress,
		NULL,
		NULL);
	if (!hRemoteThread)
		return NULL;
	::WaitForSingleObject(hRemoteThread, INFINITE);
	if (!::GetExitCodeThread(hRemoteThread, &dllBaseAddress))
		return NULL;
	::CloseHandle(hProcess);
	return (LPVOID)dllBaseAddress;
}

LPVOID injector::InjectThrowMemory(LPSTR hostName, LPTHREAD_START_ROUTINE injectThread)
{
	PROCESS_INFORMATION curPi = { 0 };
	LPVOID pImageBuffer = NULL;
	LPVOID allocBaseAddr = NULL;
	DWORD sizeOfImage = 0;
	LPTHREAD_START_ROUTINE crtStartUp = 0;

	PROCESS_INFORMATION hostPi = { 0 };

	//通过GetCurrent得到的句柄是假句柄, 只对当前进程有用, 无需CloseHandle;
	//获取自身Buffer, 当然这里完全可以换成从文件读一个dll然后展开注入, 思路一样
	Process::GetProcInfo(&curPi);
	sizeOfImage = Pe::GetSizeOfImage(::GetModuleHandleA(NULL));
	pImageBuffer = malloc(sizeOfImage);
	memcpy(pImageBuffer, ::GetModuleHandleA(NULL),sizeOfImage);

	//申请空间
	hostPi.hProcess = Process::OpenProcessM(hostName);
	if (!(allocBaseAddr = Process::VirtualAllocate(
		hostPi.hProcess,
		NULL,
		sizeOfImage,
		PAGE_EXECUTE_READWRITE
	)))
		return NULL;

	//可能出现无重定位的exe, 直接返回失败
	if (!Pe::RebaseRelocation(pImageBuffer, (DWORD)allocBaseAddr))
	{
		::VirtualFreeEx(hostPi.hProcess, allocBaseAddr, NULL, MEM_RELEASE);
		return NULL;
	}

	//写入修复重定位的Buffer, 并计算起始地址开远程线程
	::WriteProcessMemory(hostPi.hProcess, allocBaseAddr, pImageBuffer, sizeOfImage, NULL);
	crtStartUp = (LPTHREAD_START_ROUTINE)((DWORD)allocBaseAddr + (DWORD)injectThread - (DWORD)GetModuleHandle(NULL));
	hostPi.hThread = ::CreateRemoteThread(
		hostPi.hProcess,
		NULL,
		NULL,
		crtStartUp,
		allocBaseAddr,
		NULL,
		NULL);
	
	//释放句柄, 栈空间
	::WaitForSingleObject(hostPi.hThread, INFINITE);
	//如果为完全释放, 大小必须为空, 系统会按照分配时的大小释放空间
	::VirtualFreeEx(hostPi.hProcess, allocBaseAddr, NULL, MEM_RELEASE);
	free(pImageBuffer);
	Process::CloseHandles(hostPi);
	return allocBaseAddr;
}

LPVOID injector::MemoryLoadLibrary(LPSTR hostName, LPSTR moduleName)
{
	LPVOID dllImageBuffer = NULL;
	LPVOID allocBaseAddr = NULL;
	DWORD sizeOfImage = 0;
	LPTHREAD_START_ROUTINE crtStartUp = 0;
	PROCESS_INFORMATION hostPi = { 0 };

	dllImageBuffer = Pe::GetImageBuffer(moduleName);
	sizeOfImage = Pe::GetSizeOfImage(dllImageBuffer);


	//申请空间
	hostPi.hProcess = Process::OpenProcessM(hostName);
	if (!(allocBaseAddr = Process::VirtualAllocate(
		hostPi.hProcess,
		NULL,
		sizeOfImage,
		PAGE_EXECUTE_READWRITE
	)))
		return NULL;

	//可能出现无重定位的exe, 直接返回失败
	if (!Pe::RebaseRelocation(dllImageBuffer, (DWORD)allocBaseAddr))
	{
		::VirtualFreeEx(hostPi.hProcess, allocBaseAddr, NULL, MEM_RELEASE);
		return NULL;
	}

	//写入修复重定位的Buffer, 并计算起始地址开远程线程
	//这里在自身dll修复IAT, 如果适配所有的dll 那么需要导入表判断是否使用了其它dll 并递归这个过程
	::WriteProcessMemory(hostPi.hProcess, allocBaseAddr, dllImageBuffer, sizeOfImage, NULL);
	crtStartUp = (LPTHREAD_START_ROUTINE)((DWORD)allocBaseAddr + Pe::GetEntryPoint(dllImageBuffer));
	hostPi.hThread = ::CreateRemoteThread(
		hostPi.hProcess,
		NULL,
		NULL,
		crtStartUp,
		NULL,
		NULL,
		NULL);

	//释放句柄, 栈空间
	::WaitForSingleObject(hostPi.hThread, INFINITE);
	//如果为完全释放, 大小必须为空, 系统会按照分配时的大小释放空间
	::VirtualFreeEx(hostPi.hProcess, allocBaseAddr, NULL, MEM_RELEASE);
	free(dllImageBuffer);
	Process::CloseHandles(hostPi);
	return allocBaseAddr;
}
