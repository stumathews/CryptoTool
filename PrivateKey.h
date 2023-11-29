#pragma once
#include <certenroll.h>
#include <string>

class PrivateKey
{
public:
	HRESULT Initialize();
	HRESULT Uninitialize() const;
	HRESULT Create(const LONG keyLength = 2048);
	std::string GetAlgorithmName() const;
	std::string GetFriendlyName() const;
	HRESULT GetLength(std::string* outLength);
	HRESULT ExportPublicKey(IX509PublicKey** pPublicKey);
	void Print();
	IX509PrivateKey* Get() const {return pKey;}
private:
	IX509PrivateKey* pKey = nullptr;
	HRESULT hr = 0;
};


