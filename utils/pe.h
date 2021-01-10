#pragma once
#include <windows.h>
#include <WinUser.h>
#include "iostream"
#include "helpers.h"
#include "utils.h"
#pragma warning(disable:4996)
#define __BUFFER
#define __IMAGEBUFFER
#define IMAGE_ADDRESS_TABLE 4
//ƫ��Ϊ16
#define IMAGE_NAME_TABLE 0
#define ARRARY
#define MAX_IMPORT_DLL 0x20
#define MAX_IMPORT_FUNCTION 0x200
class _declspec(dllexport) Pe
{
private:
	BOOL isX64 = FALSE;
	DWORD mFileSize = 0;
	LPVOID mFileBuffer = NULL;
	__IMAGEBUFFER LPVOID mBuffer;
	struct
	{
		PIMAGE_DOS_HEADER pDosHeader = NULL;
		PIMAGE_NT_HEADERS pNTheaders = NULL;
		PIMAGE_FILE_HEADER pFileHeader = NULL;
		union
		{
			PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = NULL;
			PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64;
			PIMAGE_OPTIONAL_HEADER pOptionalHeader;
		};
		PIMAGE_SECTION_HEADER pSectionHeader = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		DWORD sectionAlignment = 0;
		DWORD fileAlignment = 0;
	}base;
private:
	DWORD InitHeaders(LPVOID pFileBuffer);
public:
	DWORD Rva2Foa(LPVOID pImageBuffer, DWORD rva);
	DWORD GetFileSize();
	DWORD GetImageBase();
	DWORD GetSizeOfImage();
	DWORD GetEntryPoint();
	LPVOID GetFileBuffer();
	DWORD GetLastSectionSizeOfRaw();
	BOOL HasRolocationTable();
public:	
	Pe(LPSTR fileName);
	Pe(LPVOID pFileBuffer, DWORD sizeOfFile);
	__IMAGEBUFFER Pe(LPVOID pImageBuffer);
	~Pe();
	//��ʼ��filebuffer���ļ���С
	DWORD InitFileBufferAndSize(LPSTR IN filePath);
	//���浽�ļ�(file ��image �Կ�)
	DWORD BufferToFile(IN LPVOID pBuffer, IN size_t sizeOfFile, OUT LPSTR outFilePath);
	//�����½�
	DWORD AllocateNewSecion(BYTE* newSectionName, DWORD newSectionSize, LPVOID newSectionBuffer, OUT LPSTR newFilePath);
	//���ImageBuffer
	LPVOID GetImageBuffer();
	//�Ƿ��Ǳ�׼pe�ļ�
	DWORD IsStandardPeFile(LPVOID pBuffer);
	//�޸��ض�λ
	__IMAGEBUFFER DWORD RebaseRelocation(DWORD newImageBase);
	//������һ�����ε�Buffer
	LPVOID GetLastSectionBuffer(LPSTR IN filePath);
public:
	//32

	static DWORD GetSizeOfImage(LPVOID pBuffer);

	//�����ļ������fb
	static LPVOID GetFileBuffer(LPSTR fileName);
	
	//����fb���ib
	static LPVOID GetImageBuffer(LPVOID pFileBuffer);

	//�����ļ������Ib
	static LPVOID GetImageBuffer(LPSTR fileName);

	static DWORD GetEntryPoint(LPVOID pBuffer);

	//����Buffer���NtHeaders
	__BUFFER static PIMAGE_NT_HEADERS GetNtHeaders(LPVOID pBuffer);

	//���Ŀ¼��
	__BUFFER static PIMAGE_DATA_DIRECTORY GetDataDirectory(LPVOID pBase);


	//ͨ�����ƻ�õ�ַ
	//�����ļ�����ImageBuffer�л�ú��������ƫ��
	static LPVOID GetFuncRVA(LPVOID pImageBuffer, LPSTR functionName);
	static LPVOID GetFuncRVA(LPVOID pImageBuffer, DWORD funcAddr);

	static LPVOID GetFirstThunkRVA(LPVOID pImageBuffer, DWORD funcAdrr);

	//ͬ�ϵ�ΪFileBuffer
	//static LPVOID GetFuncAddrFOA(LPVOID pFileBuffer, LPSTR functionName);

	//�޸��ض�λ��
	__IMAGEBUFFER static BOOL RebaseRelocation(LPVOID pImageBuffer, DWORD newImageBase);

	//�޸�IAT��
	__IMAGEBUFFER static BOOL RestoreIAT(LPVOID pImageBuffer);

	//��ӡINT/IAt
	__IMAGEBUFFER static VOID GetImageXTable(BOOL getDLLsName, LPVOID pImageBuffer, DWORD* arrData, DWORD tableType, ...);
};
//inline std::unique_ptr<Pe> shellPe;
