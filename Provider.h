#pragma once
#include <string>
#include <windows.h>

class Provider
{
public:
	explicit Provider(const LPCWSTR providerName);
	void EnumProviderKeys() const;
	NCRYPT_PROV_HANDLE GetHandle() const;
	static void ReportError(DWORD dwErrCode);
	void Open();
	std::wstring GetProperty(const std::wstring& propertyName, const DWORD dwLegacyKeySpec, const DWORD dwFlags, bool silence) const;
	LPCWSTR GetProviderName() const { return ProviderName; }
	void CreateKey(LPCWSTR keyName, bool exportable, DWORD keyLength, DWORD dwFlags = 0, LPCWSTR optionalAlgorithmName =
		               NCRYPT_ECDSA_P256_ALGORITHM, DWORD dwLegacyKeySpec = 0)  const;
	void DeleteKey(LPCWSTR keyName) const;

private:
	const LPCWSTR ProviderName;
	bool isOpen = false;
	NCRYPT_PROV_HANDLE ProviderHandle = 0;
	void CleanUp() const;
};

