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
//偏移为16
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
	//初始化filebuffer和文件大小
	DWORD InitFileBufferAndSize(LPSTR IN filePath);
	//保存到文件(file 或image 皆可)
	DWORD BufferToFile(IN LPVOID pBuffer, IN size_t sizeOfFile, OUT LPSTR outFilePath);
	//申请新节
	DWORD AllocateNewSecion(BYTE* newSectionName, DWORD newSectionSize, LPVOID newSectionBuffer, OUT LPSTR newFilePath);
	//获得ImageBuffer
	LPVOID GetImageBuffer();
	//是否是标准pe文件
	DWORD IsStandardPeFile(LPVOID pBuffer);
	//修复重定位
	__IMAGEBUFFER DWORD RebaseRelocation(DWORD newImageBase);
	//获得最后一个区段的Buffer
	LPVOID GetLastSectionBuffer(LPSTR IN filePath);
public:
	//32

	static DWORD GetSizeOfImage(LPVOID pBuffer);

	//根据文件名获得fb
	static LPVOID GetFileBuffer(LPSTR fileName);
	
	//根据fb获得ib
	static LPVOID GetImageBuffer(LPVOID pFileBuffer);

	//根据文件名获得Ib
	static LPVOID GetImageBuffer(LPSTR fileName);

	static DWORD GetEntryPoint(LPVOID pBuffer);

	//根据Buffer获得NtHeaders
	__BUFFER static PIMAGE_NT_HEADERS GetNtHeaders(LPVOID pBuffer);

	//获得目录表
	__BUFFER static PIMAGE_DATA_DIRECTORY GetDataDirectory(LPVOID pBase);


	//通过名称获得地址
	//根据文件名从ImageBuffer中获得函数的相对偏移
	static LPVOID GetFuncRVA(LPVOID pImageBuffer, LPSTR functionName);
	static LPVOID GetFuncRVA(LPVOID pImageBuffer, DWORD funcAddr);

	static LPVOID GetFirstThunkRVA(LPVOID pImageBuffer, DWORD funcAdrr);

	//同上但为FileBuffer
	//static LPVOID GetFuncAddrFOA(LPVOID pFileBuffer, LPSTR functionName);

	//修复重定位表
	__IMAGEBUFFER static BOOL RebaseRelocation(LPVOID pImageBuffer, DWORD newImageBase);

	//修复IAT表
	__IMAGEBUFFER static BOOL RestoreIAT(LPVOID pImageBuffer);

	//打印INT/IAt
	__IMAGEBUFFER static VOID GetImageXTable(BOOL getDLLsName, LPVOID pImageBuffer, DWORD* arrData, DWORD tableType, ...);
};
//inline std::unique_ptr<Pe> shellPe;
