#pragma once

#include <string>
#include <WTypes.h>

/**
 * \brief A BSTR (Basic string or binary string) is a string data type that is used by COM, Automation, and Interop functions.
 * Use the BSTR data type in all interfaces that will be accessed from script.
 */
class BStringHelper
{
public:
	static BSTR CreateBSTR(const std::wstring& string)
	{
		return SysAllocString(string.c_str());
	}

	static void FreeBSTR(BSTR& bstring)
	{
		SysFreeString(bstring);
	}

	static UINT GetLength(BSTR& bstring)
	{
		return SysStringLen(bstring);
	}
};