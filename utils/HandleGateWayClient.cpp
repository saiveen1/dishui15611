#include "HandleGateWayClient.h"

int HandleGatewayClient::ConnectPipe() {
	while (1) {
		m_pipeHandle = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

		if (m_pipeHandle != INVALID_HANDLE_VALUE)
			break; 

		if (GetLastError() != ERROR_PIPE_BUSY) { 
			printf(">>>>>管道打开失败, LastError: %d\n", (DWORD)GetLastError());
			return -1;
		}


		if (!WaitNamedPipe(PIPE_NAME, PIPEWAITTIMOUTIFBUSY)) {
			printf(">>>>>等待超时, LastError: %d\n", (DWORD)GetLastError());
			return -1;
		}
	}

	printf(">>>管道已连接.\n");

	HandleGatewayClient::SetPipeMode(PIPE_READMODE_MESSAGE);

	return 0;
}

int HandleGatewayClient::SetPipeMode(DWORD mode) {
	BOOL fSuccess = FALSE;
	fSuccess = SetNamedPipeHandleState(m_pipeHandle, &mode, NULL, NULL);
	if (!fSuccess) {
		printf(">>>>>设置管道属性失败, LastError: %d\n", (DWORD)GetLastError());
		return -1;
	}

	printf("管道属性已改变.\n");
	return 0;
}

BOOL HandleGatewayClient::DisconnectPipe() {
	return CloseHandle(m_pipeHandle);
}

bool HandleGatewayClient::RequestMsgBox()
{
	BOOL fSuccess = FALSE;
	DWORD bytesWritten = 0;
	DWORD msg = MSGBOX;
	fSuccess = WriteFile(m_pipeHandle, &msg, REQUEST_MSG, &bytesWritten, NULL);

	if (!fSuccess) {
		printf(">>>>>向管道写失败, LastError: %d\n", (DWORD)GetLastError());
		return false;
	}

	printf(">>>发送了%d个字节\n", bytesWritten);

	return true;
}

DWORD HandleGatewayClient::ReceiveMsgBox()
{
	DWORD response;
	BOOL fSuccess = FALSE;
	DWORD bytesRead = 0;

	do { // Read from the pipe.
		fSuccess = ReadFile(m_pipeHandle, &response, REQUEST_MSG, &bytesRead, NULL);

		if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
			break;

	} while (!fSuccess);  // repeat loop if ERROR_MORE_DATA 

	if (!fSuccess)
		printf(">>>>>读管道失败, LastError: %d\n", (DWORD)GetLastError());

	return response;
}

DWORD HandleGatewayClient::RemoteMsgBox()
{
	DWORD response = 0;
	if (HandleGatewayClient::RequestMsgBox()) {
		response = HandleGatewayClient::ReceiveMsgBox();
	}
	return response;
}

bool HandleGatewayClient::RequestIATHookGCD()
{
	DWORD msg = IATHOOK_GCD;
	m_fSuccess = WriteFile(m_pipeHandle, (LPCVOID)&msg, REQUEST_MSG, &m_bytesWritten, NULL);
	if (!m_fSuccess) {
		printf(">>>>>向管道写失败, LastError: %d\n", (DWORD)GetLastError());
		return false;
	}

	printf(">>>发送了%d个字节\n", m_bytesWritten);
	return TRUE;
}

ResponseIAT HandleGatewayClient::ReceiveIATHookGCD()
{
	ResponseIAT rep = { 0 };
	do { // Read from the pipe.
		m_fSuccess = ReadFile(m_pipeHandle, &rep, sizeof(ResponseIAT), &m_bytesWritten, NULL);

		if (!m_fSuccess && GetLastError() != ERROR_MORE_DATA)
			break;

	} while (!m_fSuccess);  // repeat loop if ERROR_MORE_DATA 


	if (!m_fSuccess)
		printf(">>>>>读管道失败, LastError: %d\n", (DWORD)GetLastError());

	return rep;
}

ResponseIAT HandleGatewayClient::RemoteIATHookGCD()
{
	ResponseIAT rep = { 0 };
	if (RequestIATHookGCD())
		rep = ReceiveIATHookGCD();
	return rep;
}

ResponseIAT HandleGatewayClient::Execute(DWORD code)
{
	m_fSuccess = WriteFile(m_pipeHandle, (LPCVOID)&code, REQUEST_MSG, &m_bytesWritten, NULL);
	if (!m_fSuccess) {
		printf(">>>>>向管道写失败, LastError: %d\n", (DWORD)GetLastError());
	}
	printf(">>>发送了%d个字节\n", m_bytesWritten);


	ResponseIAT rep = { 0 };
	do { // Read from the pipe.
		m_fSuccess = ReadFile(m_pipeHandle, &rep, sizeof(ResponseIAT), &m_bytesWritten, NULL);

		if (!m_fSuccess && GetLastError() != ERROR_MORE_DATA)
			break;

	} while (!m_fSuccess);  // repeat loop if ERROR_MORE_DATA 


	if (!m_fSuccess)
		printf(">>>>>读管道失败, LastError: %d\n", (DWORD)GetLastError());

	return rep;
}
