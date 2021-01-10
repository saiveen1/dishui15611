#pragma once
#include <windows.h>
#include "iostream"
class _declspec(dllexport) utils
{
public:
	template<typename T>
	static BOOL IsNULL(T arg);

	template<typename T, typename ... Ts>
	static BOOL IsNULL(T arg, Ts ...Targs);

	static wchar_t* AnsiToUnicode(const char* szStr);

	//将宽字节wchar_t*转化为单字节char*  
	static char* UnicodeToAnsi(const wchar_t* szStr);
};

template<typename T>
BOOL utils::IsNULL(T arg)
{
	if (!arg)
		return TRUE;
	return FALSE;
}

template<typename T, typename ...Ts>
BOOL utils::IsNULL(T arg, Ts ...Targs)
{
	if (!arg)
		return TRUE;
	else if (IsNULL(Targs ...))
		return TRUE;
	return FALSE;
}
/*
* a b c is null
* b c is null
* c is null2
*/
