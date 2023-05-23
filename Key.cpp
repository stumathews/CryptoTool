#include "Key.h"
#include <corecrt_wstdio.h>
#include <iostream>
#include <tchar.h>

#include "Common.h"
#include "ErrorManager.h"

extern bool IsEqual(const TCHAR* one, const TCHAR* two);

void Key::ReportError(const DWORD dwErrCode)
{
	wprintf(L"Error: 0x%08x (%i)\n", dwErrCode, dwErrCode);
	ErrorManager::PrintErrorCodeMessage(dwErrCode);
}

void Key::SetKeyExportable(const bool choice)
{
	SECURITY_STATUS secStatus;

	auto pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sizeof(int));
	if (nullptr == pBuffer)
	{
		secStatus = NTE_NO_MEMORY;
		ReportError(secStatus);
		CleanUp();
		return;
	}
	const auto bufferInput = choice == true ? NCRYPT_ALLOW_EXPORT_FLAG:0;
	memcpy_s(pBuffer, sizeof(int), &bufferInput, sizeof(int));

	std::cout << "[NCryptSetProperty (exportability)]" << std::endl;
	secStatus = NCryptSetProperty(KeyHandle, NCRYPT_EXPORT_POLICY_PROPERTY, pBuffer, sizeof(int), NCRYPT_SILENT_FLAG );

	HeapFree(GetProcessHeap(), 0, pBuffer);
	pBuffer = nullptr;

	if (FAILED(secStatus))
	{
		std::cout << "NCryptSetProperty failed." << std::endl;
		ReportError(secStatus);
		CleanUp();
	}
}

Key::Key(const std::wstring keyName, const std::wstring providerName): keyName(keyName), providerName(providerName)
{
	
}

void Key::Open()
{
	// Open handle to KSP provider

	std::cout << "[NCryptOpenStorageProvider]" << std::endl;
	SECURITY_STATUS secStatus = NCryptOpenStorageProvider(&ProviderHandle, providerName.c_str(), 0);

	if (FAILED(secStatus))
	{
		std::cout << "NCryptOpenStorageProvider failed." << std::endl;
		ReportError(secStatus);
	}

	// Open a persisted key

	secStatus = NCryptOpenKey(
		ProviderHandle,
		&KeyHandle,
		keyName.c_str(),
		0,
		0);

	if (FAILED(secStatus))
	{
		std::cout << "NCryptOpenKey failed." << std::endl;
		ReportError(secStatus);		
	}
}

void Key::SetKeyLength(const DWORD keyLength) const
{
	// Set the size of the key
	std::cout << "[NCryptSetProperty (key length)]" << std::endl;
	SECURITY_STATUS secStatus = NCryptSetProperty(
		KeyHandle,
		NCRYPT_LENGTH_PROPERTY,
		(PBYTE)&keyLength,
		sizeof(keyLength),
		NCRYPT_SILENT_FLAG);


	if (FAILED(secStatus))
	{
		std::cout << "NCryptSetProperty failed." << std::endl;
		ReportError(secStatus);
		/*if (0 != KeyHandle)
		{
			NCryptDeleteKey(KeyHandle, 0);
		}*/
		_tprintf(TEXT("Could not set key size\n"));
	}
}

bool Key::IsKeyExportable(const LPCWSTR keyName, const NCRYPT_PROV_HANDLE providerHandle, bool silence)
{
	NCRYPT_KEY_HANDLE myKeyHandle = 0; 
	// Open a persisted key

	if(!silence) { std::cout << "[NCryptOpenKey]" << std::endl; }
	SECURITY_STATUS secStatus = NCryptOpenKey(
		providerHandle,
		&myKeyHandle,
		keyName,
		0,
		0);

	if (FAILED(secStatus))
	{
		std::cout << "NCryptOpenKey failed." << std::endl;
		ReportError(secStatus);		
	}

	auto pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sizeof(int));
	DWORD writtenCount;

	if(!silence) { std::cout << "[NCryptGetProperty]" << std::endl;}
	secStatus = NCryptGetProperty(myKeyHandle, NCRYPT_EXPORT_POLICY_PROPERTY, pBuffer, sizeof(int), &writtenCount, NCRYPT_PERSIST_ONLY_FLAG);
	if (FAILED(secStatus))
	{
		std::cout << "NCryptGetProperty failed." << std::endl;
		ReportError(secStatus);
		if (0 != myKeyHandle)
		{
			myKeyHandle = 0;
		}
	}
	return static_cast<int>(*pBuffer);
}

int Key::GetKeyLength(const LPCWSTR keyName, const NCRYPT_PROV_HANDLE providerHandle,  bool silence)
{
	NCRYPT_KEY_HANDLE myKeyHandle = 0; 
	// Open a persisted key
	if(!silence) { std::cout << "[NCryptOpenKey]" << std::endl; }
	SECURITY_STATUS secStatus = NCryptOpenKey(
		providerHandle,
		&myKeyHandle,
		keyName,
		0,
		0);

	if (FAILED(secStatus))
	{
		ReportError(secStatus);		
	}

	if(!silence) { std::cout << "[NCryptGetProperty]" << std::endl; }
	DWORD keyLength = 0,outLen = 0;
	secStatus = NCryptGetProperty(myKeyHandle, NCRYPT_LENGTH_PROPERTY, (PBYTE) (&keyLength), sizeof(keyLength), &outLen, 0);
	
	if (FAILED(secStatus))
	{
		std::cout << "NCryptGetProperty failed." << std::endl;
		ReportError(secStatus);
	}
	return keyLength;
}


std::wstring Key::GetProperty(const std::wstring& propertyName, const DWORD dwLegacyKeySpec, const DWORD dwFlags,
                              bool silence) const
{
	return Common::GetProperty(KeyHandle, propertyName, silence);
}


void Key::Create(LPCWSTR keyName, NCRYPT_PROV_HANDLE providerHandle, bool exportable, const DWORD keyLength, const LPCWSTR algorithm, const DWORD
                 dwLegacyKeySpec, const DWORD dwFlags)
{
	// Create a persisted key
	std::cout << "[NCryptCreatePersistedKey]" << std::endl;
	SECURITY_STATUS secStatus = NCryptCreatePersistedKey(
		providerHandle,
		&KeyHandle,
		algorithm,
		keyName,
		dwLegacyKeySpec,
		dwFlags);

	if (FAILED(secStatus))
	{
		std::cout << "NCryptCreatePersistedKey failed." << std::endl;
		ReportError(secStatus);
		CleanUp();
		return;
	}

	SetKeyExportable(exportable);
	if(IsEqual(algorithm, L"RSA"))
	{
		SetKeyLength(keyLength);
	}

	// Finalize the key - create it on the disk
	std::cout << "[NCryptFinalizeKey]" << std::endl;
	secStatus = NCryptFinalizeKey(KeyHandle, NCRYPT_SILENT_FLAG);
	if (FAILED(secStatus))
	{
		std::cout << "NCryptFinalizeKey failed." << std::endl;
		ReportError(secStatus);
		CleanUp();
	}
}

void Key::Delete(const LPCWSTR keyName, const DWORD dwLegacyKeySpec, const DWORD dwFlags)
{
	NCRYPT_PROV_HANDLE myProviderHandle = 0;

	// Open handle to KSP
	std::cout << "[NCryptOpenStorageProvider]" << std::endl;
	SECURITY_STATUS secStatus = NCryptOpenStorageProvider(&myProviderHandle, MS_KEY_STORAGE_PROVIDER, 0);

	if (FAILED(secStatus))
	{
		std::cout << "NCryptOpenStorageProvider failed." << std::endl;
		ReportError(secStatus);
		CleanUp();
	}

	// Open a persisted key
	std::cout << "[NCryptOpenKey]" << std::endl;
	secStatus = NCryptOpenKey(
		myProviderHandle,
		&KeyHandle,
		keyName,
		dwLegacyKeySpec,
		dwFlags);

	if (FAILED(secStatus))
	{
		std::cout << "NCryptOpenKey failed." << std::endl;
		ReportError(secStatus);
		CleanUp();
	}

	if (0 != KeyHandle)
	{
		// Delete the key
		std::cout << "[NCryptDeleteKey]" << std::endl;
		secStatus = NCryptDeleteKey(KeyHandle, 0);
		if (FAILED(secStatus))
		{
			std::cout << "NCryptDeleteKey failed." << std::endl;
			ReportError(secStatus);
			CleanUp();
		}
		KeyHandle = 0;
	}
}

void Key::CleanUp()
{
	if (0 != KeyHandle)
	{
		std::cout << "[NCryptDeleteKey]" << std::endl;
		NCryptDeleteKey(KeyHandle, 0);
		KeyHandle = 0;
	}
}
