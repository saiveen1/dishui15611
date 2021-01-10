#pragma once
#include <windows.h>
#include <iostream>
#include "pipeMsg.h"

// ----------------------------------------------------
// Client class (to use in the cheat)
// ----------------------------------------------------

class _declspec(dllexport) HandleGatewayClient {
public:
	int ConnectPipe();
	BOOL DisconnectPipe();
	int SetPipeMode(DWORD mode = { PIPE_READMODE_MESSAGE });


	//简单的printf通信
	bool RequestMsgBox();
	DWORD ReceiveMsgBox();
	DWORD RemoteMsgBox();

	bool RequestIATHookGCD();
	ResponseIAT ReceiveIATHookGCD();
	ResponseIAT RemoteIATHookGCD();

	ResponseIAT Execute(DWORD code);


protected:
	HANDLE m_pipeHandle = INVALID_HANDLE_VALUE;
	LPTSTR qwe = (LPTSTR)TEXT("\\\\.\\pipe\\namedPipe");
	BOOL m_fSuccess = FALSE;
	DWORD m_bytesWritten = 0;
};
