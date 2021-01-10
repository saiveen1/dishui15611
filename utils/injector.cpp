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
	DWORD dwImageBaseDelta = dwNewImageBase - pOptionHeader->ImageBase; // �¾�ImageBase �Ĳ�ֵ	
	if (!pOptionHeader->DataDirectory[5].VirtualAddress)
	{
		pOptionHeader->ImageBase = dwImageBaseDelta;
		return;
	}
	// �ض�λ��� VirtualAddress + ��12λƫ�� = RVA
	// RVA + ImageBase ����ڴ���洢��һ����ָ�롱
	// Ҫ�޸ĵ��������ָ�롱��ֵ��Ҫ�������ָ�롱��������ImageBase�Ĳ�ֵ
	while (pRelocationTable->VirtualAddress || pRelocationTable->SizeOfBlock)
	{
		size_t n = (pRelocationTable->SizeOfBlock - 8) / 2; // ������Ҫ�޸ĵĵ�ַ��������4λ==0011��Ҫ�޸ģ�
		PWORD pOffset = (PWORD)((DWORD)pRelocationTable + 8); // 2�ֽ�ƫ�Ƶ�����
		for (size_t i = 0; i < n; i++)
		{
			// ��4λ����0011����Ҫ�ض�λ
			if ((pOffset[i] & 0xF000) == 0x3000)
			{
				// ������Ҫ�ض�λ�����ݵ�RVA��ַ
				DWORD dwRva = pRelocationTable->VirtualAddress + (pOffset[i] & 0x0FFF);
				// �����ھ����еĵ�ַ
				PDWORD pData = (PDWORD)((DWORD)pImageBuffer + dwRva);
				// �ض�λ��������д���ĵ�ַ				
				*pData += dwImageBaseDelta;
			}
		}
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	// �޸� ImageBase
	pOptionHeader->ImageBase = dwNewImageBase;
}



/// <summary>
/// ���߳�A�п�Զ���߳�, ��Ϊloadlibrary�ĵ��ø�ʽ���̻߳ص�һ������
/// ����ֱ�ӽ��䵱���̺߳���ʹ��, ��Ϊ��user32���Ե�ַ��һ��
/// ���е�dll������Ҫ���߳�A������ռ�, Ȼ�����
/// </summary>
/// <param name="processName"></param>
/// <param name="dllName"></param>
/// <returns>ע��dll��baseAddress</returns>
LPVOID injector::InjectByRemoteThread(LPWSTR injectProcName, LPWSTR dllName)
{

	HANDLE hProcess = 0;
	HANDLE hRemoteThread = 0;
	LPVOID dllNameAdrress = NULL;
	DWORD dllBaseAddress = NULL;
	TCHAR dllFullPath[MAX_PATH];
	//dll һ��Ҫ��ȡ����·��, ��Ϊ��A���������Ҳ�����dll��
	::GetFullPathName(dllName, MAX_PATH, dllFullPath, NULL);
	hProcess = Process::OpenProcessM(injectProcName);
	//�ڽ���������ռ��dll����, ��������, �������ռ伴��
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

	//ͨ��GetCurrent�õ��ľ���Ǽپ��, ֻ�Ե�ǰ��������, ����CloseHandle;
	//��ȡ����Buffer, ��Ȼ������ȫ���Ի��ɴ��ļ���һ��dllȻ��չ��ע��, ˼·һ��
	Process::GetProcInfo(&curPi);
	sizeOfImage = Pe::GetSizeOfImage(::GetModuleHandleA(NULL));
	pImageBuffer = malloc(sizeOfImage);
	memcpy(pImageBuffer, ::GetModuleHandleA(NULL),sizeOfImage);

	//����ռ�
	hostPi.hProcess = Process::OpenProcessM(hostName);
	if (!(allocBaseAddr = Process::VirtualAllocate(
		hostPi.hProcess,
		NULL,
		sizeOfImage,
		PAGE_EXECUTE_READWRITE
	)))
		return NULL;

	//���ܳ������ض�λ��exe, ֱ�ӷ���ʧ��
	if (!Pe::RebaseRelocation(pImageBuffer, (DWORD)allocBaseAddr))
	{
		::VirtualFreeEx(hostPi.hProcess, allocBaseAddr, NULL, MEM_RELEASE);
		return NULL;
	}

	//д���޸��ض�λ��Buffer, ��������ʼ��ַ��Զ���߳�
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
	
	//�ͷž��, ջ�ռ�
	::WaitForSingleObject(hostPi.hThread, INFINITE);
	//���Ϊ��ȫ�ͷ�, ��С����Ϊ��, ϵͳ�ᰴ�շ���ʱ�Ĵ�С�ͷſռ�
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


	//����ռ�
	hostPi.hProcess = Process::OpenProcessM(hostName);
	if (!(allocBaseAddr = Process::VirtualAllocate(
		hostPi.hProcess,
		NULL,
		sizeOfImage,
		PAGE_EXECUTE_READWRITE
	)))
		return NULL;

	//���ܳ������ض�λ��exe, ֱ�ӷ���ʧ��
	if (!Pe::RebaseRelocation(dllImageBuffer, (DWORD)allocBaseAddr))
	{
		::VirtualFreeEx(hostPi.hProcess, allocBaseAddr, NULL, MEM_RELEASE);
		return NULL;
	}

	//д���޸��ض�λ��Buffer, ��������ʼ��ַ��Զ���߳�
	//����������dll�޸�IAT, ����������е�dll ��ô��Ҫ������ж��Ƿ�ʹ��������dll ���ݹ��������
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

	//�ͷž��, ջ�ռ�
	::WaitForSingleObject(hostPi.hThread, INFINITE);
	//���Ϊ��ȫ�ͷ�, ��С����Ϊ��, ϵͳ�ᰴ�շ���ʱ�Ĵ�С�ͷſռ�
	::VirtualFreeEx(hostPi.hProcess, allocBaseAddr, NULL, MEM_RELEASE);
	free(dllImageBuffer);
	Process::CloseHandles(hostPi);
	return allocBaseAddr;
}
