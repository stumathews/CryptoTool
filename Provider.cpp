#include "Provider.h"

#include <vector>
#include <memory>

#include "ErrorManager.h"
#include "Key.h"
#include <iostream>

#include "Common.h"

extern bool IsEqual(const TCHAR* one, const TCHAR* two);

Provider::Provider(const LPCWSTR providerName): ProviderName(providerName)
{}

void Provider::EnumProviderKeys() const
{	
	// Handle for the cryptographic provider context.
	HCRYPTPROV hProvider;

	NCryptOpenStorageProvider(&hProvider, ProviderName , NULL);

	NCryptKeyName *pKeyName = nullptr;
	PVOID pState = nullptr;
	std::vector<std::shared_ptr<NCRYPT_KEY_HANDLE>> keyHandles;
	SECURITY_STATUS secStatus;

	auto count = 0;
	while ((secStatus = NCryptEnumKeys(hProvider, 0, &pKeyName, &pState, 0)) != NTE_NO_MORE_ITEMS)
	{
		if (secStatus != ERROR_SUCCESS) 
		{
			printf("Error: NCryptEnumKeys : 0x%x\n", secStatus);
			ErrorManager::PrintErrorCodeMessage(GetLastError());
			return;
		}

		count++;		
		std::shared_ptr<NCRYPT_KEY_HANDLE> hKey(new NCRYPT_KEY_HANDLE);

		keyHandles.push_back(hKey);

		secStatus = NCryptOpenKey(hProvider, hKey.get(), pKeyName->pszName,pKeyName->dwLegacyKeySpec, 0);
		if (FAILED(secStatus))
		{
			std::cout << "NCryptOpenKey failed." << std::endl;
			ReportError(secStatus);
			CleanUp();
		}

		wprintf(L"%d: Name=%s Algorithm=%s LegacyKeySpec=%d Flags=%d Exportable=%d ",
			count,
			pKeyName->pszName, 
			pKeyName->pszAlgid, 
			pKeyName->dwLegacyKeySpec, 
			pKeyName->dwFlags, 
			Key::IsKeyExportable(pKeyName->pszName, hProvider, true));

		if(IsEqual(pKeyName->pszAlgid, L"RSA"))
		{
			wprintf(L"Length: %d", Key::GetKeyLength(pKeyName->pszName, hProvider));
		}

		wprintf(L"\n");
	}

	NCryptFreeBuffer((PVOID)hProvider);
}

NCRYPT_PROV_HANDLE Provider::GetHandle() const
{
	if(isOpen)
	{
		return ProviderHandle;
	}
	std::cout << "Provider is not Open." << std::endl;
	return 0;
}

void Provider::ReportError(DWORD dwErrCode)
{
	wprintf(L"Error: 0x%08x (%d)\n", dwErrCode, dwErrCode);
	ErrorManager::PrintErrorCodeMessage(dwErrCode);
}

void Provider::Open()
{
	// Open handle to KSP
	const SECURITY_STATUS secStatus = NCryptOpenStorageProvider(&ProviderHandle, ProviderName, 0);
	if (FAILED(secStatus))
	{
		std::cout << "NCryptOpenStorageProvider failed." << std::endl;
		isOpen = false;
		ReportError(secStatus);
		CleanUp();
	}
	isOpen = true;
}

std::wstring Provider::GetProperty(const std::wstring& propertyName, const DWORD dwLegacyKeySpec, const DWORD dwFlags,
                              bool silence) const
{
	return Common::GetProperty(ProviderHandle, propertyName, silence);
}

void Provider::CreateKey(LPCWSTR keyName, bool exportable,  DWORD keyLength, DWORD dwFlags,  LPCWSTR optionalAlgorithmName, DWORD dwLegacyKeySpec) const
{
	Key key(keyName, ProviderName);
	key.Create(keyName, ProviderHandle, exportable, keyLength, optionalAlgorithmName, dwLegacyKeySpec, dwFlags);
	if(!key.IsKeyHandleValid())
	{
		std::cout << "Key is not valid" << std::endl;
	}
}

void Provider::DeleteKey(LPCWSTR keyName) const
{
	Key key(keyName, ProviderName);
	key.Delete(keyName);
}

void Provider::CleanUp() const
{
	if (0 != ProviderHandle)
	{
		NCryptFreeObject(ProviderHandle);
	}
}
