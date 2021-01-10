
#include "HookFunc.h"

//原始函数地址区
/* IAThook可以直接写成用函数名传递来Hook, 这样也符合
*/
LPVOID pOldGetClipboardData = GetProcAddress(LoadLibraryA("user32.dll"), "GetClipboardData");
LPVOID pOldCreateProcessW = GetProcAddress(LoadLibraryA("kernel32.dll"), "CreateProcessW");
LPVOID pOldMsgBoxA = GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");

char hookMsg[] = "Hook succeed!";

char* msgAddr = hookMsg;
Registers regs = { 0 };
//MsgBoxArgs args = { 0 };





//75BA8BA0 8B FF                mov         edi, edi
//75BA8BA2 55                   push        ebp
//75BA8BA3 8B EC                mov         ebp, esp
TCHAR hookProc[] = L"d:\\demo.exe";
Proc args = { 0 };
BOOL excuteFlag = FALSE;	//标志hook函数被执行, Server 显示各参数(可以写成向客户端传, 但这样客户端也要有个实时监听, 先不弄了)
DWORD retAddr = (DWORD)pOldCreateProcessW + 5;


void __declspec(naked) CreateProcessM()
{
	__asm 
	{
		PUSHAD;
		PUSHFD;
	}


	//CreateProcessW(
	//	_In_opt_ LPCWSTR lpApplicationName,
	//	_Inout_opt_ LPWSTR lpCommandLine,
	//	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	//	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	//	_In_ BOOL bInheritHandles,
	//	_In_ DWORD dwCreationFlags,
	//	_In_opt_ LPVOID lpEnvironment,
	//	_In_opt_ LPCWSTR lpCurrentDirectory,
	//	_In_ LPSTARTUPINFOW lpStartupInfo,
	//	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	//);


	__asm
	{
		mov eax, [esp + 0x2c];
		mov args.lpAppName, eax;
		mov eax, [esp + 0x30];
		mov args.lpCommandLine, eax;
		mov eax, [esp + 0x44];
		mov args.lpEnvironment, eax;
		mov eax, [esp + 0x48];
		mov args.lpCurrentDirectory, eax;


	}
	MessageBox(NULL, args.lpAppName, L"原本要打开的进程.", NULL);

	__asm
	{
		//改变第一个参数
		lea eax, [esp + 0x2c];
		lea edi, hookProc;
		mov[eax], edi;
		mov eax, [esp + 0x2c];
		mov args.lpAppName, eax;
		//这里不能使用寄存器跳, 因为最后要恢复所有寄存器.
		add DWORD ptr pOldCreateProcessW, 5;
	}
	MessageBox(NULL, args.lpAppName, L"Hooked!", NULL);
	//执行原先的代码并jmp到hook地址+5
	__asm
	{
		popfd;
		popad;

		mov edi, edi;
		push ebp;
		mov ebp, esp;

		//jmp retAddr
		jmp pOldCreateProcessW;
	}
}

HANDLE __stdcall HookGetClipboardData(UINT uFormat)
{
	typedef HANDLE(WINAPI* PGetClipboardData) (_In_ UINT uFormat);
	PGetClipboardData GetClipboardData = (PGetClipboardData)pOldGetClipboardData;
	HANDLE hMem = GetClipboardData(uFormat);
	LPWSTR clipData = (LPWSTR)hMem;
	MessageBox(NULL, clipData, L"剪切板已被Hook", NULL);


	DWORD dataSize = wcslen(clipData);
	memset(clipData, 0, dataSize);
	LPWSTR hookData = (LPWSTR)L"Hooked!";
	wcscpy(clipData, hookData);
	return hMem;
}
