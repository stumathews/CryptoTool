#include "PrivateKey.h"

#include <comutil.h>
#include <iostream>
#include <string>
#include "ErrorManager.h"

HRESULT PrivateKey::Initialize()
{
	// Create IX509PrivateKey
	hr = CoCreateInstance(
		__uuidof(CX509PrivateKey),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		__uuidof(IX509PrivateKey),
		(void **) &pKey);

	return hr;
}

HRESULT PrivateKey::Create(const LONG keyLength)
{
	// Make sure the key is 2048 bits long
	pKey->put_Length(keyLength);

	// Create the key
	hr = pKey->Create();

	return hr;
}

Either<HRESULT, std::string> PrivateKey::GetLength()
{
	LONG length;
	hr = pKey->get_Length(&length);
	if(hr == S_OK)
	{
		return std::to_string(length);
	}
	return hr;
	
}

HRESULT PrivateKey::ExportPublicKey(IX509PublicKey** pPublicKey)
{
	hr = pKey->ExportPublicKey(pPublicKey);
	return hr;
}

std::string PrivateKey::GetAlgorithmName() const
{
	IObjectId* objectId;
	std::string algorithmName;

	if(pKey->get_Algorithm(&objectId) == S_OK)
	{
		BSTR algoFriendlyName;
		if(objectId->get_FriendlyName(&algoFriendlyName) == S_OK)
		{			
			algorithmName = std::string(_bstr_t(algoFriendlyName, true));
			SysFreeString(algoFriendlyName);
		}
		else
		{
			algorithmName= "";
		}
	}
	return algorithmName;
}


HRESULT PrivateKey::Uninitialize()
{
	if (nullptr != pKey) pKey->Release();
	return hr;
}
