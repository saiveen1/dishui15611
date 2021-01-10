#pragma once
#include "pipemsg.h"
#include "HookFunc.h"
#include "hook.h"
// ----------------------------------------------------
// Server class (to inject in the process having a handle to the target process)
// �����, ע�뵽��������Ŀ����̵ľ��
// ----------------------------------------------------

class _declspec(dllexport) HandleGatewayServer {
public:
	int Init();
	int Gateway();
	BOOL AnswerMsg();
	BOOL ExecIATHook();
	BOOL UnIATHook();
	BOOL ExecInlineHook();
	BOOL UnInline();
protected:
	BOOL m_clientConnected = FALSE;
	DWORD  m_threadId = 0;
	HANDLE m_pipeHandle = INVALID_HANDLE_VALUE;
	LPTSTR qwe = (LPTSTR)TEXT("\\\\.\\pipe\\namedPipe");
	BOOL m_fSuccess = FALSE;
	DWORD m_bytesWritten = 0;
};
