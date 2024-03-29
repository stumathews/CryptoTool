#include "Common.h"

#include <iostream>


void Common::ReportError(DWORD dwErrCode)
{
	wprintf(L"Error: 0x%08x (%d)\n", dwErrCode, dwErrCode);
	ErrorManager::PrintErrorCodeMessage(dwErrCode);
}

void Common::LogIfError(DWORD hr, const char* message)
{
	if (S_OK != hr) 
    { 
        std::cout << L"Error: " << message << ", Code:" << hr << std::endl; 
        ErrorManager::PrintErrorCodeMessage(hr);
    } 
}

std::wstring Common::ToWString(std::string str)
{
	std::string orig = str;
    const size_t newsizew = orig.size() + 1;
    size_t convertedChars = 0;
    wchar_t* wcstring = new wchar_t[newsizew];
    mbstowcs_s(&convertedChars, wcstring, newsizew, orig.c_str(), _TRUNCATE);

    std::wstring w = wcstring;
	delete []wcstring;
	return w;
}

std::wstring Common::GetProperty(const NCRYPT_HANDLE object, const std::wstring& propertyName, bool silence)
{
	const wchar_t* property;

	if(IsEqual(propertyName.c_str(), L"NCRYPT_UNIQUE_NAME_PROPERTY"))
	{
		property = NCRYPT_UNIQUE_NAME_PROPERTY;
	}
	else if(IsEqual(propertyName.c_str(), L"NCRYPT_NAME_PROPERTY"))
	{
		property = NCRYPT_NAME_PROPERTY;

	} else
	{
		return {};
	}

	constexpr auto bufferLength = 128;
	constexpr auto sizeBytes = sizeof(TCHAR) * bufferLength;
	const auto pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sizeBytes);

	if(pBuffer == nullptr)
	{
		return {};
	}
	DWORD writtenCount;

	if(!silence) { std::cout << "[NCryptGetProperty]" << std::endl;}
	const SECURITY_STATUS secStatus = NCryptGetProperty(object, property, pBuffer, sizeBytes, &writtenCount, NCRYPT_SILENT_FLAG);
	if (FAILED(secStatus))
	{
		std::cout << "NCryptGetProperty failed." << std::endl;
		ReportError(secStatus);
		return {};					
	}

	return std::wstring(reinterpret_cast<wchar_t*>(pBuffer), sizeBytes);
}
