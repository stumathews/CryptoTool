#pragma once
#include <string>
#include <windows.h>
class Key
{
public:
	Key() = delete;
	Key(std::wstring keyName, std::wstring providerName);
	void Open();
	NCRYPT_KEY_HANDLE GetHandle() const { return KeyHandle; }
	bool IsKeyHandleValid() const { return  KeyHandle != 0;}
	void SetKeyLength(const DWORD keyLength) const;
	void Create(LPCWSTR keyName, NCRYPT_PROV_HANDLE providerHandle, bool exportable, const DWORD keyLength = 2048, LPCWSTR algorithm =
		            NCRYPT_ECDSA_P256_ALGORITHM, DWORD dwLegacyKeySpec = 0, DWORD dwFlags = 0);
	void Delete(const LPCWSTR CERTSRV_E_KEY_ATTESTATION_NOT_SUPPORTEDame, const DWORD dwLegacyKeySpec = 0, const DWORD dwFlags = 0);	
	static bool IsKeyExportable(const LPCWSTR keyName, const NCRYPT_PROV_HANDLE providerHandle, bool silence = true);
	static int GetKeyLength(const LPCWSTR keyName, const NCRYPT_PROV_HANDLE providerHandle, bool silence = true);

	std::wstring GetProperty(const std::wstring& propertyName, const DWORD dwLegacyKeySpec, const DWORD dwFlags,
	                         bool silence = true) const;

private:
	std::wstring keyName;
	std::wstring providerName;
	NCRYPT_KEY_HANDLE KeyHandle = 0;
	NCRYPT_PROV_HANDLE ProviderHandle = 0;
	static void ReportError(DWORD dwErrCode);
	void SetKeyExportable(bool choice);


	void CleanUp();
};

