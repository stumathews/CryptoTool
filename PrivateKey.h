#pragma once
#include "Either.h"
#include <certenroll.h>
#include <string>

class PrivateKey
{
public:
	HRESULT Initialize();
	HRESULT Uninitialize();
	HRESULT Create(const LONG keyLength = 2048);
	std::string GetAlgorithmName() const;
	Either<HRESULT, std::string> GetLength();
private:
	IX509PrivateKey* pKey = nullptr;
	HRESULT hr = 0;
};

