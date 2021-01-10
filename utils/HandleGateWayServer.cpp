#include "HandleGateWayServer.h"

extern LPVOID pOldGetClipboardData;
extern LPVOID pOldCreateProcessW;

int HandleGatewayServer::Init() 
{
	while (1) {
		m_pipeHandle = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, MAXPIPEFILESIZE, MAXPIPEFILESIZE, 0, NULL);
		printf(">>>管道建立成功, 等待客户端.\n");
		if (m_pipeHandle == INVALID_HANDLE_VALUE) {
			printf(">>>>>管道建立失败, LastError: %d\n", (DWORD)GetLastError());
			system("pause");
			return -1;
		}

		//等待客户端连接, 如果成功, 返回非零值, 否则GetLastError返回ERROR_PIP_CONNECTED
		m_clientConnected = ConnectNamedPipe(m_pipeHandle, NULL);
		if (m_clientConnected) {
			printf(">>>客户端已连接, 建立网关\n");
			if (HandleGatewayServer::Gateway() == 2)
				return -1;
		}
		else {
			CloseHandle(m_pipeHandle);
		}
	}

	return 0;
}

//extern BOOL excuteFlag;
//extern Proc args;
int HandleGatewayServer::Gateway() 
{
	HANDLE hHeap = ::GetProcessHeap();
	void* request = ::HeapAlloc(hHeap, 0, REQUEST_MSG);
	if (!request)
		return -1;
	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;
	DWORD orderID = 0;
	while (1) { // Loop until done reading
		fSuccess = ReadFile(m_pipeHandle, request, REQUEST_MSG, &cbBytesRead, NULL);
		if (!fSuccess || cbBytesRead == 0) {
			if (GetLastError() == ERROR_BROKEN_PIPE) {
				printf(">>>>>客户端连接失败, LastError: %d\n", (DWORD)GetLastError());
			}
			else {
				printf(">>>>>读管道失败, LastError: %d\n", (DWORD)GetLastError());
			}
			//printf(">>>当前没有数据.\n");
			break;
		}

		orderID = *(DWORD*)request;

		switch (orderID)
		{
		case MSGBOX:
			AnswerMsg();
			break;
		case IATHOOK_GCD:
			ExecIATHook();
			break;
		case UNIATHOOK:
			UnIATHook();
			break;
		case INLINEHOOK_CREATEPROCESS:
			ExecInlineHook();
			break;
		case UNINLIEHOOK:
			UnInline();
			break;
		case DISCONNECT:
			// Flush the pipe to allow the client to read the pipe's contents before disconnecting.
			// Then disconnect the pipe, and close the handle to this pipe instance. 
			FlushFileBuffers(m_pipeHandle);
			DisconnectNamedPipe(m_pipeHandle);
			CloseHandle(m_pipeHandle);

			HeapFree(hHeap, 0, request);

			printf("管道连接已关闭, 任意键退出\n");
			//system("pause");
			return 2;
		default:
			printf(">>>>>未知命令, Order: %d\n", orderID);
			break;
		}

	}
	return 0;
}

BOOL HandleGatewayServer::AnswerMsg()
{
	BOOL fSuccess = FALSE;
	DWORD bytesWritten = 0;
	DWORD msg = 1;
	MessageBoxA(NULL, "执行消息成功", "来自客户端的指令", 0);
	fSuccess = WriteFile(m_pipeHandle, &msg, REQUEST_MSG, &bytesWritten, NULL);
	if (!fSuccess)
		printf(">>>>>写管道失败, LastError: %d\n", (DWORD)GetLastError());
	printf(">>>执行了打开MessageBox指令.\n");
	return TRUE;
}

BOOL HandleGatewayServer::ExecIATHook()
{
	ResponseIAT rep = { 0 };
	rep.status = hook::IATHOOK(GetModuleHandleA("cloudmusic.dll"), pOldGetClipboardData, HookGetClipboardData);
	rep.args = NULL;
	m_fSuccess = WriteFile(m_pipeHandle, &rep, sizeof(ResponseIAT), &m_bytesWritten, NULL);
	if (!m_fSuccess)
		printf(">>>>>写管道失败, LastError: %d\n", (DWORD)GetLastError());
	printf(">>>执行了IAThook, 将剪切板数据改变.\n");
	return TRUE;
}

BOOL HandleGatewayServer::UnIATHook()
{
	ResponseIAT rep = { 0 };
	rep.status = hook::IATHOOK(GetModuleHandleA("cloudmusic.dll"), HookGetClipboardData, pOldGetClipboardData);
	rep.args = NULL;
	m_fSuccess = WriteFile(m_pipeHandle, &rep, sizeof(ResponseIAT), &m_bytesWritten, NULL);
	if (!m_fSuccess)
		printf(">>>>>写管道失败, LastError: %d\n", (DWORD)GetLastError());
	printf(">>>卸载了IAThook.\n");
	return TRUE;
}

BYTE* pOldBytes = NULL;
BOOL HandleGatewayServer::ExecInlineHook()
{
	pOldBytes = new BYTE[5];
	ResponseIAT rep = { 0 };
	rep.status = hook::InlineHook(pOldCreateProcessW, CreateProcessM, pOldBytes);
	rep.args = NULL;
	m_fSuccess = WriteFile(m_pipeHandle, &rep, sizeof(ResponseIAT), &m_bytesWritten, NULL);
	if (!m_fSuccess)
		printf(">>>>>写管道失败, LastError: %d\n", (DWORD)GetLastError());
	printf(">>>执行了InlineHook, 开通会员被hook\n");
	return TRUE;
}

BOOL HandleGatewayServer::UnInline()
{
	pOldBytes = new BYTE[5]{ 0 };
	ResponseIAT rep = { 0 };
	rep.status = hook::UnInlineHook(pOldCreateProcessW, pOldBytes);
	rep.args = NULL;
	m_fSuccess = WriteFile(m_pipeHandle, &rep, sizeof(ResponseIAT), &m_bytesWritten, NULL);
	if (!m_fSuccess)
		printf(">>>>>写管道失败, LastError: %d\n", (DWORD)GetLastError());
	printf(">>>卸载了InlineHook.\n");
	return TRUE;
}


