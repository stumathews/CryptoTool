#pragma once
#include <strsafe.h>
#include <string>
#include "ErrorManager.h"

extern bool IsEqual(const TCHAR* one, const TCHAR* two);

class Common
{
public:
	static std::wstring GetProperty(const NCRYPT_HANDLE object, const std::wstring& propertyName, bool silence);
	static void ReportError(DWORD dwErrCode);
};

