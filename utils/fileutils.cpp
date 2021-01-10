#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

const IMAGE_NT_HEADERS* GetNtHeader(const BYTE* image, const DWORD imageSize)
{
	const IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)image;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		wprintf(L"Invalid DOS header\n");
		return NULL;
	}
	const IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((ULONG_PTR)image + dosHeader->e_lfanew);
	if ((BYTE*)ntHeader < image) {
		wprintf(L"Invalid NT header\n");
		return NULL;
	}
	if ((BYTE*)ntHeader > (image + imageSize - sizeof(IMAGE_NT_HEADERS))) {
		wprintf(L"Invalid NT header\n");
		return NULL;
	}
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		wprintf(L"Invalid NT header\n");
		return NULL;
	}
	return ntHeader;
}

BOOL ReadFileData(WCHAR* filename, BYTE** buff, DWORD* size)
{
	if (filename == NULL || buff == NULL || size == NULL)
		return FALSE;

	HANDLE hFile = CreateFileW(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	// get size of file
	LARGE_INTEGER liSize;
	if (!GetFileSizeEx(hFile, &liSize)) {
		CloseHandle(hFile);
		return FALSE;
	}
	if (liSize.HighPart > 0) {
		CloseHandle(hFile);
		return FALSE;
	}

	// read entire file into memory
	*buff = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, liSize.LowPart);
	if (*buff == NULL) {
		CloseHandle(hFile);
		return FALSE;
	}
	BYTE* buffPtr = *buff;
	DWORD numLeft = liSize.LowPart;
	DWORD numRead = 0;
	while (numLeft > 0) {
		if (!ReadFile(hFile, buffPtr, numLeft, &numRead, NULL)) {
			CloseHandle(hFile);
			HeapFree(GetProcessHeap(), 0, *buff);
			return FALSE;
		}
		numLeft -= numRead;
		buffPtr += numRead;
	}
	*size = liSize.LowPart;
	CloseHandle(hFile);
	return TRUE;
}