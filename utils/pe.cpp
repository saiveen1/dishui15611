#include "Pe.h"
Pe::Pe(LPSTR fileName)
{
	InitFileBufferAndSize(fileName);
	InitHeaders(mFileBuffer);
}
Pe::Pe(LPVOID pFileBuffer, DWORD sizeOfFile)
{
	mFileBuffer = pFileBuffer;
	InitHeaders(mFileBuffer);
	mFileSize = sizeOfFile;
}
__IMAGEBUFFER Pe::Pe(LPVOID pImageBuffer)
{
	mFileBuffer = pImageBuffer;
	InitHeaders(mFileBuffer);
}
Pe::~Pe()
{
	free(mFileBuffer);
}

LPVOID Pe::GetFileBuffer(LPSTR fileName)
{
	HANDLE hFile = 0;
	DWORD sizeOfFile = 0;
	DWORD read = 0;
	LPVOID pFileBuffer = 0;
	char szFullPath[MAX_PATH] = { 0 };
	GetFullPathNameA(fileName, MAX_PATH, szFullPath, NULL);
	hFile = CreateFileA(szFullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); // Open the replacement executable
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	sizeOfFile = ::GetFileSize(hFile, NULL); // Get the size of the replacement executable
	pFileBuffer = VirtualAlloc(NULL, sizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate memory for the executable file
	if (!ReadFile(hFile, pFileBuffer, sizeOfFile, &read, NULL)) // Read the executable file from disk
		return NULL;
	return pFileBuffer;
}

LPVOID Pe::GetImageBuffer(LPVOID pFileBuffer)
{
	LPVOID pImageBuffer = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = GetNtHeaders(pFileBuffer);
	//0x18 optionalheader的偏移
	PIMAGE_SECTION_HEADER pSectionHeader= (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + 0x18 + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	if (!(pImageBuffer = malloc(pNtHeaders->OptionalHeader.SizeOfImage)))
		return 0;
	memset(pImageBuffer, 0, pNtHeaders->OptionalHeader.SizeOfImage);
	memcpy(pImageBuffer, pFileBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);
	for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		//大小用大的 size of raw data
		memcpy((LPVOID)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress), (LPVOID)((DWORD)pFileBuffer + pSectionHeader->PointerToRawData),  pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}
	return pImageBuffer;
}

LPVOID Pe::GetImageBuffer(LPSTR fileName)
{
	LPVOID pImageBuffer = NULL;
	LPVOID pFileBuffer = GetFileBuffer(fileName);
	return GetImageBuffer(pFileBuffer);
}

DWORD Pe::GetSizeOfImage(LPVOID pBuffer)
{
	return GetNtHeaders(pBuffer)->OptionalHeader.SizeOfImage;
}

PIMAGE_DATA_DIRECTORY Pe::GetDataDirectory(LPVOID pBase)
{
	return (PIMAGE_DATA_DIRECTORY)(GetNtHeaders(pBase)->OptionalHeader.DataDirectory);
}

DWORD Pe::InitHeaders(LPVOID pFileBuffer)
{
	base.pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//pNTheaders = (PIMAGE_NT_HEADERS)((QWORD)pDosHeader + pDosHeader->e_lfanew);
	base.pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)base.pDosHeader + base.pDosHeader->e_lfanew + 0x4);
	base.pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)base.pFileHeader + 0x14);
	//
	if (base.pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64 || base.pFileHeader->Machine == IMAGE_FILE_MACHINE_IA64)
	{
		isX64 = TRUE;
		base.pSectionHeader = (PIMAGE_SECTION_HEADER)((QWORD)base.pOptionalHeader64 + base.pFileHeader->SizeOfOptionalHeader);
		base.pDataDirectory = base.pOptionalHeader64->DataDirectory;
	}
	else
	{
		isX64 = FALSE;
		base.pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)base.pOptionalHeader64;
		base.pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)base.pOptionalHeader32 + base.pFileHeader->SizeOfOptionalHeader);
		base.pDataDirectory = base.pOptionalHeader32->DataDirectory;
	}
	base.sectionAlignment = base.pOptionalHeader->SectionAlignment;
	base.fileAlignment = base.pOptionalHeader->FileAlignment;
	return 1;
}

DWORD Pe::InitFileBufferAndSize(LPSTR IN filePath)
{
	FILE* pFile = NULL;
	//Open file.
	if (!(pFile = fopen(filePath, "rb")))
	{
		printf("Can't open the executable file");
		exit(OPEN_FILE_FAILED);
	}
	//Read the length of file.
	fseek(pFile, 0, SEEK_END);
	mFileSize = ftell(pFile);
	//Allocate memory.
	//写到sectionAllocate才发现这个问题 编译器会自动在分配空间的后面+0x30个空间
	if (!(mFileBuffer = (LPVOID)malloc(mFileSize)))
	{
		printf("Allocate memory failed.");
		fclose(pFile);
		exit(0);
	}
	fseek(pFile, 0, SEEK_SET);
	size_t n = fread(mFileBuffer, mFileSize, 1, pFile);
	//成功返回1
	if (!n)
	{
		printf("Read data failed!");
		free(mFileBuffer);
		fclose(pFile);
		exit(0);
	}
	fclose(pFile);
	return 1;
}

DWORD Pe::IsStandardPeFile(LPVOID pBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (*(PWORD)pBuffer != IMAGE_DOS_SIGNATURE)
	{
		printf("It's not a available MZ signature.");
		free(pBuffer);
		return FALSE;
	}
	if (*((PDWORD)((DWORD)pBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("It's not a available PE signature.");
		free(pBuffer);
		return FALSE;
	}
	return TRUE;
}

DWORD __BUFFER Pe::RebaseRelocation(DWORD newImageBase)
{
	DWORD foaBaseRelocation = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;
	InitHeaders(mFileBuffer);
	pDataDirectory = base.pOptionalHeader->DataDirectory;
	foaBaseRelocation = Rva2Foa(mFileBuffer, (*(pDataDirectory + 5)).VirtualAddress);
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)mFileBuffer + foaBaseRelocation);
	DWORD foaOfData = 0;
	DWORD rvaOfData = 0;
	DWORD currentBlockItems = 0;
	DWORD foaOfBlock = 0;
	DWORD differenceOfImageBase = 0;
	DWORD addressOf_rvaOfData = 0;
	DWORD* pFarAddress = NULL;
	differenceOfImageBase = newImageBase - base.pOptionalHeader->ImageBase;
	base.pOptionalHeader->ImageBase = newImageBase;
	while (pBaseRelocation->SizeOfBlock)
	{
		//要修改的数据大表在文件中的偏移 大表 + word 型偏移
		foaOfBlock = (DWORD)pBaseRelocation - (DWORD)mFileBuffer;
		currentBlockItems = (pBaseRelocation->SizeOfBlock - 8) / 2;	//word 表示
		addressOf_rvaOfData = pBaseRelocation->VirtualAddress;
		while (--currentBlockItems)
		{
			rvaOfData = ((*(WORD*)(foaOfBlock + (DWORD)mFileBuffer + 8)) & 0x0fff) + addressOf_rvaOfData;
			foaOfData = (DWORD)Rva2Foa(mFileBuffer, rvaOfData);
			pFarAddress = (DWORD*)(foaOfData + (DWORD)mFileBuffer);
			*pFarAddress += differenceOfImageBase;
			foaOfBlock += 2;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}
	return 1;
}

PIMAGE_NT_HEADERS Pe::GetNtHeaders(LPVOID pBuffer)
{
	return (PIMAGE_NT_HEADERS)((DWORD)pBuffer + *((DWORD*)((DWORD)(pBuffer)+0x3c)));
}

BOOL Pe::RebaseRelocation(LPVOID pImageBuffer, DWORD newImageBase)
{
	DWORD rvaBaseRelocation = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	pNtHeaders = GetNtHeaders(pImageBuffer);
	pDataDirectory = pNtHeaders->OptionalHeader.DataDirectory;
	rvaBaseRelocation = (*(pDataDirectory + 5)).VirtualAddress;
	if (!rvaBaseRelocation)
	{
		MessageBoxA(NULL, "软件无重定位!!! 无法更改ImageBase", "Error", NULL);
		return FALSE;
	}
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBuffer + rvaBaseRelocation);
	DWORD foaOfData = 0;
	DWORD rvaOfData = 0;
	DWORD currentBlockItems = 0;
	DWORD foaOfBlock = 0;
	DWORD differenceOfImageBase = 0;
	DWORD addressOf_rvaOfData = 0;
	DWORD* pFarAddress = NULL;
	differenceOfImageBase = newImageBase - pNtHeaders->OptionalHeader.ImageBase;
	pNtHeaders->OptionalHeader.ImageBase = newImageBase;
	while (pBaseRelocation->SizeOfBlock)
	{
		//要修改的数据大表在文件中的偏移 大表 + word 型偏移
		foaOfBlock = (DWORD)pBaseRelocation - (DWORD)pImageBuffer;
		currentBlockItems = (pBaseRelocation->SizeOfBlock - 8) / 2;	//word 表示
		addressOf_rvaOfData = pBaseRelocation->VirtualAddress;
		while (--currentBlockItems)
		{
			rvaOfData = ((*(WORD*)(foaOfBlock + (DWORD)pImageBuffer + 8)) & 0x0fff) + addressOf_rvaOfData;
			pFarAddress = (DWORD*)(rvaOfData + (DWORD)pImageBuffer);
			*pFarAddress += differenceOfImageBase;
			foaOfBlock += 2;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}
	return TRUE;
}

BOOL Pe::RestoreIAT(LPVOID pImageBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;
	HMODULE hModule = 0;
	DWORD rvaImport = 0;
	DWORD rvaName = 0;
	DWORD rvaOriginalThunk = 0;
	DWORD rvaFirstThunk = 0;
	DWORD originalValue = 0;
	LPVOID pFirstValue = NULL;
	DWORD ordinalOfFunc = 0;
	CHAR* pFuncNameAddr = NULL;
	DWORD oldProtect = 0;

	pNtHeaders = GetNtHeaders(pImageBuffer);
	rvaImport = (*(pNtHeaders->OptionalHeader.DataDirectory + 1)).VirtualAddress;
	pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageBuffer + rvaImport);

	//以OriginalFirstThunk为基准找到函数名/序号
	//将新值补充到FirstThunk对应的ThunkValue中
	while (rvaOriginalThunk = *((DWORD*)pImport))
	{
		rvaFirstThunk = *((DWORD*)pImport + 4);
		rvaName = pImport->Name;
		if (!(hModule = ::LoadLibraryA((CHAR*)(DWORD)pImageBuffer + rvaName)))
		{
			//这一句不能加, printf 的dll可能没加载导致程序异常退出.
			//printf("加载dll失败 LastError: %d", GetLastError());
			return FALSE;
		}
		//printf("DLL's name: %s\n", (char*)((DWORD)pImageBuffer + rvaName));
		while (originalValue = *(DWORD*)((DWORD)pImageBuffer + (DWORD)rvaOriginalThunk))
		{
			pFirstValue = (LPVOID)((DWORD)pImageBuffer + rvaFirstThunk);
			VirtualProtect(pFirstValue, 4, PAGE_READWRITE, &oldProtect);
			if ((originalValue & 0x80000000) == 0x80000000)
			{
				ordinalOfFunc = (originalValue & 0x7FFFFFFF);
				*(DWORD*)pFirstValue = (DWORD)GetProcAddress(hModule, MAKEINTRESOURCEA(ordinalOfFunc));
			}
			else
			{
				//data 为地址或名称取决于表类型
				pFuncNameAddr = (CHAR*)((DWORD)pImageBuffer + originalValue + 2);
				*(DWORD*)pFirstValue = (DWORD)GetProcAddress(hModule, pFuncNameAddr);
			}
			rvaOriginalThunk += 4;
		}
		pImport++;
	}
	return TRUE;
}

/*************************************************
Function: GetFunctionAddrByName
Description: 通过函数名字获得函数地址相当于GetProcAddress
Calls:
Called By:
Table Accessed:
Table Updated:
Input: filePath	标准PE文件的字符串格式 pFileBuffer 文件缓冲区
Output:
Return:
*************************************************/
LPVOID Pe::GetFuncRVA(LPVOID pImageBuffer, LPSTR functionName)
{
	DWORD rvaExportDirectory = 0;
	DWORD i = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	DWORD currentNameOrdinal = 0;
	DWORD addrOfNameOrdinals = 0;
	DWORD addrOfFunctions = 0;
	pNtHeaders = GetNtHeaders(pImageBuffer);
	pDataDirectory = pNtHeaders->OptionalHeader.DataDirectory;
	rvaExportDirectory = pDataDirectory->VirtualAddress;
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(rvaExportDirectory + (DWORD)pImageBuffer);
	DWORD addrOfNames = pExportDirectory->AddressOfNames;
	for (i; i < pExportDirectory->NumberOfNames; i++)
	{
		//坑爹的系统函数 相等竟然是为0
		if (!strcmp(functionName, (char*)((DWORD)pImageBuffer + *(DWORD*)((DWORD)pImageBuffer + addrOfNames))))
			break;
		addrOfNames += 4;
	}
	//addrNames与addrOrdinals一致, 最后通过addrFunctions找到地址
	addrOfNameOrdinals = pExportDirectory->AddressOfNameOrdinals;
	currentNameOrdinal = *((WORD*)((DWORD)(pImageBuffer) + addrOfNameOrdinals) + i);
	addrOfFunctions = pExportDirectory->AddressOfFunctions;
	//addrFunctions + 序号就为当前函数的地址
	LPVOID ans = (LPVOID)(*((DWORD*)((DWORD)pImageBuffer + addrOfFunctions) + currentNameOrdinal));
	return ans;
}


LPVOID Pe::GetFuncRVA(LPVOID pImageBuffer, DWORD funcAddr)
{
	DWORD rvaExportDirectory = 0;
	DWORD i = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	DWORD currentNameOrdinal = 0;
	DWORD addrOfNameOrdinals = 0;
	DWORD addrOfFunctions = 0;
	pNtHeaders = GetNtHeaders(pImageBuffer);
	pDataDirectory = pNtHeaders->OptionalHeader.DataDirectory;
	rvaExportDirectory = pDataDirectory->VirtualAddress;
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(rvaExportDirectory + (DWORD)pImageBuffer);
	DWORD addrOfFunc = pExportDirectory->AddressOfFunctions;
	for (i; i < pExportDirectory->NumberOfNames; i++)
	{
		//坑爹的系统函数 相等竟然是为0
		if (!(funcAddr == *(DWORD*)((DWORD)pImageBuffer + *(DWORD*)((DWORD)pImageBuffer + addrOfFunc))))
			break;
		addrOfFunc += 4;
	}
	//addrNames与addrOrdinals一致, 最后通过addrFunctions找到地址
	addrOfNameOrdinals = pExportDirectory->AddressOfNameOrdinals;
	currentNameOrdinal = *((WORD*)((DWORD)(pImageBuffer) + addrOfNameOrdinals) + i);
	addrOfFunc = pExportDirectory->AddressOfFunctions;
	//addrFunctions + 序号就为当前函数的地址
	LPVOID ans = (LPVOID)(*((DWORD*)((DWORD)pImageBuffer + addrOfFunctions) + currentNameOrdinal));
	return ans;
}

LPVOID Pe::GetFirstThunkRVA(LPVOID pImageBuffer, DWORD funcAdrr)
{
	DWORD rvaImportDescriptor = 0;
	DWORD rvaName = 0;
	DWORD thunkValue = 0;
	DWORD ordinalOfFunction = 0;
	LPVOID dataAddress = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	LPVOID pThunk = NULL;
	//设定有0x100个函数如果不够后面再用virtualallocate申请

	pNtHeaders = GetNtHeaders(pImageBuffer);
	//rvaImportDescriptor = (*(pNtHeaders->OptionalHeader->DataDirectory + 1)).VirtualAddress;
	rvaImportDescriptor = (*(pNtHeaders->OptionalHeader.DataDirectory + 1)).VirtualAddress;
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageBuffer + rvaImportDescriptor);
	//FirstThunk指向IAT也就是要修复的地址
	//又不能只单单加载FirstThunk, 必须要从OriginalFirstThunk获得INT即函数名称...
	pThunk = (LPVOID)(*((DWORD*)pImportDescriptor + IMAGE_ADDRESS_TABLE));
	BOOL flag = FALSE;
	while (pThunk)
	{

		//printf("DLL's name: %s\n", (char*)((DWORD)pImageBuffer + rvaName));
		thunkValue = *(DWORD*)((DWORD)pImageBuffer + (DWORD)pThunk);
		while (thunkValue)
		{
			if (thunkValue == funcAdrr)
			{
				flag = TRUE;
				break;
			}

			pThunk = (LPVOID)((DWORD)pThunk + 4);
			thunkValue = *(DWORD*)((DWORD)pImageBuffer + (DWORD)pThunk);
		}
		if (flag)
			break;
		pImportDescriptor++;
		pThunk = (LPVOID)(*((DWORD*)pImportDescriptor + IMAGE_ADDRESS_TABLE));

	}
	return pThunk;
}


/// <summary>
/// 获取IAT或者INT表
/// </summary>
/// <param name="pImageBuffer">需要内存镜像</param>
/// <param name="arrData">out 参数保存的数据地址</param>
/// <param name="tableType">表类型</param>
/// <param name="getDLLsName">是否获取dll名称</param>
/// <param name="">可变参数 如果上个参数为True则放一个数组存储dll名称</param>
VOID Pe::GetImageXTable(BOOL getDLLsName, LPVOID pImageBuffer, DWORD* arrData, DWORD tableType, ...)
{
	DWORD rvaImportDescriptor = 0;
	DWORD rvaName = 0;
	DWORD thunkValue = 0;
	DWORD ordinalOfFunction = 0;
	LPVOID dataAddress = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	LPVOID pThunk = NULL;
	//设定有0x100个函数如果不够后面再用virtualallocate申请
	char** arrDLLsNameAddr = {NULL};
	if (getDLLsName)
	{
		va_list arg;
		va_start(arg, getDLLsName);
		//arrDLLsNameAddr
		for (int i = 0; i < 4; i++)
			arrDLLsNameAddr = (CHAR**)va_arg(arg, LPVOID);
		va_end(arg);
	}
	pNtHeaders = GetNtHeaders(pImageBuffer);
	rvaImportDescriptor = (*(pNtHeaders->OptionalHeader.DataDirectory + 1)).VirtualAddress;
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageBuffer + rvaImportDescriptor);
	pThunk = (LPVOID)(*((DWORD*)pImportDescriptor + tableType));
	while (pThunk)
	{
		if (getDLLsName)
		{
			rvaName = pImportDescriptor->Name;
			*arrDLLsNameAddr = (CHAR *)(DWORD)pImageBuffer + rvaName;
			arrDLLsNameAddr++;
		}
		//printf("DLL's name: %s\n", (char*)((DWORD)pImageBuffer + rvaName));
		thunkValue = *(DWORD*)((DWORD)pImageBuffer + (DWORD)pThunk);
		while (thunkValue)
		{
			if ((thunkValue & 0x80000000) == 0x80000000)
			{
				ordinalOfFunction = (thunkValue & 0x7FFFFFFF);
				TODO;
			}
			else
			{
				//data 为地址或名称取决于表类型
				dataAddress = (LPVOID)((DWORD)pImageBuffer + thunkValue + 2);
				*arrData = (DWORD)dataAddress;
				arrData++;
			}
			pThunk = (LPVOID)((DWORD)pThunk + 4);
			thunkValue = *(DWORD*)((DWORD)pImageBuffer + (DWORD)pThunk);
		}
		pImportDescriptor++;
		pThunk = (LPVOID)(*((DWORD*)pImportDescriptor + tableType));
	}
	
}

LPVOID Pe::GetLastSectionBuffer(LPSTR IN filePath)
{
	InitFileBufferAndSize(filePath);
	InitHeaders(mFileBuffer);
	//从零开始......
	PIMAGE_SECTION_HEADER pLastSectionHeader = base.pSectionHeader + base.pFileHeader->NumberOfSections - 1;
	return (LPVOID)((DWORD)mFileBuffer + (pLastSectionHeader - 1)->PointerToRawData + (pLastSectionHeader - 1)->SizeOfRawData);
}

DWORD Pe::GetFileSize()
{
	return mFileSize;
}

DWORD Pe::GetImageBase()
{
	return base.pOptionalHeader->ImageBase;
}

DWORD Pe::GetSizeOfImage()
{
	return base.pOptionalHeader->SizeOfImage;
}

DWORD Pe::GetEntryPoint()
{
	return base.pOptionalHeader->AddressOfEntryPoint;
}

DWORD Pe::GetEntryPoint(LPVOID pBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = GetNtHeaders(pBuffer);
	return pNtHeaders->OptionalHeader.AddressOfEntryPoint;
}

LPVOID Pe::GetFileBuffer()
{
	return mFileBuffer;
}

DWORD Pe::GetLastSectionSizeOfRaw()
{
	return (base.pSectionHeader + base.pFileHeader->NumberOfSections - 1)->SizeOfRawData;
}

BOOL Pe::HasRolocationTable()
{
	return *(DWORD *)(base.pOptionalHeader->DataDirectory + 5);
}

DWORD Pe::Rva2Foa(LPVOID pImageBuffer, DWORD rva)
{
	DWORD virtualAddress = 0;
	DWORD imageSectionSize = 0;
	InitHeaders(pImageBuffer);
	//5.18在做绑定导出表的时候 RVA 250返回0显然错的 , 没有想到在区段前的数据 如果在, 直接返回即可
	if (rva < base.pSectionHeader->PointerToRawData)
		return rva;
	PIMAGE_SECTION_HEADER pSectionTmp = base.pSectionHeader;
	for (DWORD i = 0; i < base.pFileHeader->NumberOfSections; i++)
	{
		virtualAddress = pSectionTmp->VirtualAddress;
		imageSectionSize = virtualAddress + pSectionTmp->Misc.VirtualSize;
		if (rva >= virtualAddress && rva < imageSectionSize)
			return rva - virtualAddress + pSectionTmp->PointerToRawData;	//fileOffset
		pSectionTmp++;
	}
	return 0;
}

DWORD Pe::BufferToFile(IN LPVOID pBuffer, IN size_t sizeOfFile, OUT LPSTR outFilePath)
{
	FILE* pfile = NULL;
	if (!(pfile = fopen(outFilePath, "wb")))
	{
		printf("Create file failed.");
		exit(0);
	}
	if (!fwrite(pBuffer, sizeOfFile, 1, pfile))
	{
		printf("Create a executable file failed.");
		fclose(pfile);
		return 0;
	}
	if (!IsStandardPeFile(pBuffer))
	{
		printf("保存出错不是标准PE文件.");
		fclose(pfile);
		return 0;
	}
	fclose(pfile);
	return sizeOfFile;
}

/// <summary>
/// 增加一个节
/// </summary>
/// <param name="newSectionName"></param>
/// <param name="newSectionSize"></param>
/// <param name="newSectionBuffer"></param>
/// <param name="newFilePath">out参数得到新文件路径, 直接生成新文件</param>
/// <returns>是否成功</returns>
DWORD Pe::AllocateNewSecion(BYTE *newSectionName, DWORD newSectionSize, LPVOID newSectionBuffer, OUT LPSTR newFilePath)
{
	DWORD sizeOfAllocation = 0;
	DWORD sizeOfDosStub = 0;
	DWORD foaNewSection = 0;
	LPVOID pNewFileBuffer = NULL;
	PIMAGE_SECTION_HEADER newSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pOriginalLastSectionHeader = base.pSectionHeader + base.pFileHeader->NumberOfSections - 1;
	//if ((DWORD)base.pOptionalHeader->SizeOfHeaders-(DWORD)(base.pSectionHeader+base.pFileHeader->NumberOfSections))
	//{
	//	//删去Dos Stub, 将PE头直接指向(dos 头和pe 头中间的数据)
	//	DWORD dw_temp = base.pDosHeader->e_lfanew;
	//	base.pDosHeader->e_lfanew = SIZE_OF_DOSHEADER;
	//	//整体向上移当然oep也要
	//	sizeOfDosStub = dw_temp - SIZE_OF_DOSHEADER;
	//	base.pOptionalHeader32->AddressOfEntryPoint -= sizeOfDosStub;
	//	//如果
	//	if (sizeOfDosStub < 0x40)
	//	{
	//		printf("DosStub小于0x40,需要整体移动才能申请新节\n.");
	//		exit(-1);
	//	}
	//	//sizeOfHeaders大小-ntHeaders的大小
	//	sizeOfAllocation = (DWORD)(base.pDosHeader+base.pOptionalHeader->SizeOfHeaders) + IMAGE_SIZEOF_SECTION_HEADER - (DWORD)base.pNTheaders;
	//	memcpy((LPVOID)((DWORD)base.pDosHeader + SIZE_OF_DOSHEADER), (LPVOID)base.pNTheaders, sizeOfAllocation);
	//}
	sizeOfAllocation = newSectionSize;
	base.pFileHeader->NumberOfSections++;
	base.pOptionalHeader->SizeOfImage += newSectionSize;
	//12.21不考虑区段最后的垃圾数据(非dos stub) 版权信息
	foaNewSection = pOriginalLastSectionHeader->SizeOfRawData + pOriginalLastSectionHeader->PointerToRawData;
	mFileSize += sizeOfAllocation;
	if (!(pNewFileBuffer = (LPVOID)malloc(mFileSize)))
		return 0;
	memset(pNewFileBuffer, 0, mFileSize);
	memcpy(pNewFileBuffer, mFileBuffer, mFileSize - sizeOfAllocation);
	InitHeaders(pNewFileBuffer);
	//复制第一个区段的信息
	newSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)(base.pSectionHeader + base.pFileHeader->NumberOfSections - 1));
	memcpy(newSectionHeader, base.pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	memset(newSectionHeader + 1, 0, IMAGE_SIZEOF_SECTION_HEADER);
	
	//改变新节信息
	//这里需要特别注意, 由于这个区段是用来解密释放的, 所以并不需要执行怎么样, 给0也可以, 但为了隐藏身份可以随便给一个或者给src的大小	
	//区段计算, (virtualsize / sectionalignment + 1) * sectionalignment, 整个区段的大小
	//如果是非整数倍就需要多加一个对齐来保证数据在该区段
	//如果整数倍 那么该多少对齐就用多少对齐
	for (DWORD i = 0; i < SIZE_OF_SECTION_NAME; i++)
		newSectionHeader->Name[i] = newSectionName[i];
	newSectionHeader->SizeOfRawData = newSectionSize;
	newSectionHeader->Misc.VirtualSize = newSectionSize;
	DWORD dw_temp = pOriginalLastSectionHeader->Misc.VirtualSize / base.sectionAlignment;
	if (pOriginalLastSectionHeader->Misc.VirtualSize % base.sectionAlignment)	
		newSectionHeader->VirtualAddress = (newSectionHeader - 1)->VirtualAddress + (dw_temp + 1) * base.sectionAlignment;
	else
		newSectionHeader->VirtualAddress = (newSectionHeader - 1)->VirtualAddress + (dw_temp - 1) * base.sectionAlignment;
	newSectionHeader->PointerToRawData = (newSectionHeader - 1)->PointerToRawData + (newSectionHeader - 1)->SizeOfRawData;
	//5.25太致命的错误了 section的Characteristic因为要插入dll写死了CALL地址 需要获取地址然后传入到里面 代表此块可写 然后一直没发现这个问题
	//或运算, 一个为1就为1
	newSectionHeader->Characteristics |= 0xf0000000;
	LPVOID newSectionAddress = (LPVOID)((DWORD)pNewFileBuffer + pOriginalLastSectionHeader->PointerToRawData + pOriginalLastSectionHeader->SizeOfRawData);
	memcpy(newSectionAddress, newSectionBuffer, newSectionSize);
	if ((base.pFileHeader->Characteristics & 0x2000) == IMAGE_FILE_DLL)
	{
		//BufferToFile(pNewFileBuffer, fileSize, newSectionOutFilePathForDLL);
		//*addrOutFilePath = (DWORD)newSectionOutFilePathForDLL;
		TODO;
	}
	else
		BufferToFile(pNewFileBuffer, mFileSize, newFilePath);
	free(pNewFileBuffer);
	return foaNewSection;
}

LPVOID Pe::GetImageBuffer()
{
	LPVOID pImageBuffer = NULL;
	InitHeaders(mFileBuffer);
	if (!IsStandardPeFile(mFileBuffer))
	{
		printf("IMAGETOFILE出错.");
		free(mFileBuffer);
		return 0;
	}
	if (!(pImageBuffer = malloc(base.pOptionalHeader->SizeOfImage)))
		return 0;
	memset(pImageBuffer, 0, base.pOptionalHeader->SizeOfImage);
	memcpy(pImageBuffer, mFileBuffer, base.pOptionalHeader->SizeOfHeaders);
	for (DWORD i = 0; i < base.pFileHeader->NumberOfSections; i++)
	{
		//大小用大的 size of raw data
		memcpy((LPVOID)((DWORD)pImageBuffer + base.pSectionHeader->VirtualAddress), (LPVOID)((DWORD)mFileBuffer + base.pSectionHeader->PointerToRawData), base.pSectionHeader->SizeOfRawData);
		base.pSectionHeader++;
	}
	if (!IsStandardPeFile(mFileBuffer))
	{
		printf("Copy from FileBuffer to ImageBuffer failed.\n");
		free(pImageBuffer);
		free(mFileBuffer);
		return NULL;
	}
	return pImageBuffer;
}
