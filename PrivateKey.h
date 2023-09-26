#pragma once
#include <certenroll.h>
#include <string>

class PrivateKey
{
public:
	HRESULT Initialize();
	HRESULT Uninitialize();
	HRESULT Create(const LONG keyLength = 2048);
	std::string GetAlgorithmName() const;
	HRESULT GetLength(std::string* outLength);
	HRESULT ExportPublicKey(IX509PublicKey** pPublicKey);
	void Print();
private:
	IX509PrivateKey* pKey = nullptr;
	HRESULT hr = 0;
};


