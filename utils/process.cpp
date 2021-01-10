#include "process.h"

//Unicode 设置下无CreateA函数, 宽字符无奈之举
DWORD Process::GetPID(LPWSTR processName)
{
	HANDLE hProcessSnap = 0;
	if (!(hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)))
		return 0;
	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(procEntry);
	do 
	{
		if (!wcsicmp(processName, procEntry.szExeFile))
		{
			::CloseHandle(hProcessSnap);
			return procEntry.th32ProcessID;
		}
	} while (::Process32Next(hProcessSnap, &procEntry));
	return 0;
}

BOOL Process::GetProcInfo(PROCESS_INFORMATION* pi)
{
	pi->hProcess = ::GetCurrentProcess();
	pi->hThread = ::GetCurrentThread();
	if (pi->hProcess == pi->hThread)
		return FALSE;
	return TRUE;
}

DWORD Process::GetModuleAddr(DWORD PID,LPWSTR moduleName, DWORD* sizeOfModule, CHAR* moduleFullPath)
{
	HANDLE hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		return 0;
	}
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!wcsicmp(moduleName, L"VCRUNTIME140D.dll"))
	{
		memset(moduleName, 0, 0x20);
		wcscpy(moduleName, L"VCRUNTIME140.dll");
	}
	if (!wcsicmp(moduleName, L"ucrtbased.dll"))
	{
		memset(moduleName, 0, 0x20);
		wcscpy(moduleName, L"ucrtbase.dll");
	}
	do
	{
		printf("%s\n", utils::UnicodeToAnsi(moduleEntry.szModule));
		//一定要不区分大小写, 用api获取的为.DLL ...
		if (!wcsicmp(moduleName, moduleEntry.szModule))
		{
			::CloseHandle(hModuleSnap);
			*sizeOfModule = moduleEntry.modBaseSize;
			strcpy(moduleFullPath, utils::UnicodeToAnsi(moduleEntry.szExePath));
			printf("\n\n");
			return (DWORD)moduleEntry.modBaseAddr;
		}
	} while (::Module32Next(hModuleSnap, &moduleEntry));
	return 0;
}

DWORD Process::GetModuleAddr(LPSTR hostName, LPSTR moduleName)
{
	DWORD PID = GetPID(utils::AnsiToUnicode(hostName));
	LPWSTR moduleNameW = utils::AnsiToUnicode(moduleName);
	HANDLE hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		return 0;
	}
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	do
	{
		//一定要不区分大小写, 用api获取的为.DLL ...
		if (!wcsicmp(moduleNameW, moduleEntry.szModule))
		{
			::CloseHandle(hModuleSnap);
			return (DWORD)moduleEntry.modBaseAddr;
		}
	} while (::Module32Next(hModuleSnap, &moduleEntry));
	return 0;
}

LPVOID Process::VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t, DWORD protect)
{
	if (!pAddress)
		pAddress = ::VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		);
	else if (pAddress = ::VirtualAllocEx(
		hProcess,
		NULL,
		size_t,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	))
	{
		//如果不成功, 这里会报487内存访问错误, 很正常, 因为申请源地址有东西
		printf("GetLastError: %d\n", (int)GetLastError());
		//printf("ImageBase被占用, 将随机申请空间. 请修复重定位表");
		LPVOID newImageBase = NULL;
		if ((newImageBase = ::VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		)))
			return newImageBase;
		return NULL;
	}
	//FreeLibrary(hModuleKernel);
	return pAddress;
}
BOOL Process::VirtualFreeM(DWORD pid,LPVOID lpAddr)
{
	HANDLE hProc = OpenProcessM(pid);
	if (VirtualFreeEx(hProc, lpAddr, NULL, MEM_RELEASE))
	{
		CloseHandle(hProc);
		return TRUE;
	}
	return FALSE;
}
//minimize
//记得CloseHandle
HANDLE Process::OpenProcessM(DWORD pid)
{
	HANDLE hProcess = 0;
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	return hProcess;
}

HANDLE Process::OpenProcessM(CHAR* procName)
{
	HANDLE hProcess = 0;
	DWORD pid = GetPID(utils::AnsiToUnicode(procName));
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	return hProcess;
}

HANDLE Process::OpenProcessM(WCHAR* procName)
{
	HANDLE hProcess = 0;
	DWORD pid = GetPID(procName);
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	return hProcess;
}

PROCESS_INFORMATION Process::CreateProcessSuspend(LPSTR processName)
{
	STARTUPINFOA src_si = { 0 };
	PROCESS_INFORMATION src_pi;
	src_si.cb = sizeof(src_si);
	//以挂起的方式创建进程		
	//这个警告可以忽略, 因为需要对线程做操作, 最后其他的地方会调用CloseHandle
	CreateProcessA(
		NULL,                    // name of executable module					
		processName,                // command line string					
		NULL, 					 // SD
		NULL,  		             // SD			
		FALSE,                   // handle inheritance option					
		CREATE_SUSPENDED,     	 // creation flags  				
		NULL,                    // new environment block					
		NULL,                    // current directory name					
		&src_si,                  // startup information					
		&src_pi                   // process information					
	);
	return src_pi;
}

VOID Process::CloseHandles(PROCESS_INFORMATION src_pi)
{
	
	//WaitForSingleObject(src_pi.hProcess, INFINITE);
	::CloseHandle(src_pi.hProcess);
	::CloseHandle(src_pi.hThread);
}

CONTEXT Process::GetThreadContext(HANDLE hThread)
{
	CONTEXT ct;
	ct.ContextFlags = CONTEXT_FULL;
	//获取主线程信息 ImageBase 入口点	
	::GetThreadContext(hThread, &ct);
	return ct;
}

DWORD Process::GetThreadImageBase(PROCESS_INFORMATION procInfo)
{
	char* baseAddress = (CHAR*)GetThreadContext(procInfo.hThread).Ebx + 8;
	DWORD ImageBase = 0;
	ReadProcessMemory(procInfo.hProcess, baseAddress, &ImageBase, 4, NULL);
	return ImageBase;
}

LPVOID Process::GetThreadImageBuffer(PROCESS_INFORMATION procInfo, OUT DWORD* sizeOfImage)
{
	DWORD imageBase = GetThreadImageBase(procInfo);
	//可以使用偏移读到SizeOfImage
	//这里被视频影响, 其实可以不必从内存中读自己, 主需要获取当前文件路径从硬盘读也行
	//23.17还是不能从文件里面读, 这样就降低了效率(申请空间给FileBuffer再到ImageBuffer, 效率也降低)
	//Pe injector
	//dosheader->3c == elfanew->0x50 == SizeOfImage
	LPVOID pImageBuffer = NULL;
	ReadProcessMemory(procInfo.hProcess, GET_SIZEOFIMAGE_OFFSET(imageBase), sizeOfImage, 4, NULL);
	if (!(pImageBuffer = malloc(*sizeOfImage)))
		return NULL;
	ReadProcessMemory(procInfo.hProcess, (LPCVOID)imageBase, pImageBuffer, *sizeOfImage, NULL);
	return pImageBuffer;
}

__IMAGEBUFFER BOOL Process::RestoreImageAddrTable(LPVOID pImageBuffer, DWORD hostPID, HANDLE hProcHost)
{
	CHAR** arrDLLsName = NULL;
	DWORD* arrFuncName = NULL;
	DWORD* arrFuncAddr = NULL;
	LPCSTR dllName = NULL;
	LPSTR funcName = NULL;
	DWORD moduleBase = NULL;
	DWORD sizeOfModule = 0;
	LPVOID pModuleImgBuffer = NULL;
	DWORD lastError = 0;
	HMODULE hModule = 0;
	CHAR* modulePath = new CHAR[MAX_PATH];
	//20个dll*最大字符长度空间
	arrDLLsName = new CHAR* [MAX_IMPORT_DLL * MAX_PATH]{ 0 };
	arrFuncName = new DWORD[MAX_IMPORT_FUNCTION]{ 0 };
	arrFuncAddr = new DWORD[MAX_IMPORT_FUNCTION]{ 0 };
	if (utils::IsNULL(arrDLLsName, arrFuncName, arrFuncAddr))
		return 0;
	Pe::GetImageXTable(TRUE, pImageBuffer, arrFuncName, IMAGE_NAME_TABLE, arrDLLsName);
	Pe::GetImageXTable(FALSE, pImageBuffer, arrFuncAddr, IMAGE_ADDRESS_TABLE);
	while (*arrDLLsName)
	{
		//判断宿主是否加载了寄生程序所需要的dll
		dllName = (LPCSTR)(*(arrDLLsName));
		//if(!(hModule=LoadLibraryA))

		if (!(moduleBase = Process::GetModuleAddr(hostPID, utils::AnsiToUnicode(dllName), &sizeOfModule, modulePath)))
		{
			arrDLLsName++;
			continue;
		}

		pModuleImgBuffer = malloc(sizeOfModule);
		DWORD a = Process::EnableDebugPrivileges();
		DWORD b = GetLastError();
		DWORD s = 0;
		::ReadProcessMemory(hProcHost, (LPCVOID)moduleBase, pModuleImgBuffer, sizeOfModule, &s);
		DWORD c = GetLastError();
		pModuleImgBuffer = Pe::GetImageBuffer((LPSTR)modulePath);
		memset(modulePath, 0, MAX_PATH);
		while (*arrFuncName)
		{
			funcName = (LPSTR)(*arrFuncName);
			//可能存在没有获取到地址为0
			*arrFuncAddr = (DWORD)(Pe::GetFuncRVA(pModuleImgBuffer, funcName));
			arrFuncName++;
			arrFuncAddr++;
			
		}
		free(pModuleImgBuffer);
		arrDLLsName++;
	}
	//还要减去原来的
	//delete[]arrDLLsName;
	//delete[]arrFuncAddr;
	//delete[]arrFuncName;
	//delete[]modulePath;
	return TRUE;
}

DWORD Process::VirProtect(LPVOID addr, DWORD dwLength, DWORD flNewProtect)
{
	DWORD preProtect = 0;
	//第四个参数不能传NULL!!!
	return VirtualProtect(addr, dwLength, flNewProtect, &preProtect);
}

DWORD Process::WriteCurrentMemory(LPVOID baseAddr, LPVOID buffer, DWORD length)
{
	HANDLE hCurrProc = GetCurrentProcess();
	if (!hCurrProc)
		return -1;
	DWORD writtenBytes = 0;
	::WriteProcessMemory(hCurrProc, baseAddr, (LPCVOID)buffer, length, &writtenBytes);
	CloseHandle(hCurrProc);
	return writtenBytes;
}

BOOL Process::EnableDebugPrivileges(void)
{
	HANDLE token;
	TOKEN_PRIVILEGES priv;
	BOOL ret = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid) != FALSE &&
			AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE)
		{
			ret = TRUE;
		}
		CloseHandle(token);
	}
	return ret;
}
