#pragma once
#include "process.h"



class _declspec(dllexport) injector
{
public:
	static LPVOID InjectByRemoteThread(LPWSTR injectProcName, LPWSTR dllName);
	//ע�뺯���費��Ҫ�����Լ�������, �Ͼ�ֻ�Ǹ�demo
	//����ע�� Ŀ�����, ��������
	static LPVOID InjectThrowMemory(LPSTR hostName, LPTHREAD_START_ROUTINE parasitic);

	//��ģ���ڴ�ע��dll
	//��Ҫdll�����޸�IAT, ����ͨ��
	static LPVOID MemoryLoadLibrary(LPSTR hostName, LPSTR moduleName);
};

