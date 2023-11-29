#include "PrivateKey.h"

#include <comutil.h>
#include <iostream>
#include <string>

#include "Common.h"

HRESULT PrivateKey::Initialize()
{
	// Create IX509PrivateKey
	hr = CoCreateInstance(
		__uuidof(CX509PrivateKey),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		__uuidof(IX509PrivateKey),
		(void **) &pKey);

	Common::LogIfError(hr, "CoCreate CX509PrivateKey failed");

	return hr;
}

HRESULT PrivateKey::Create(const LONG keyLength)
{
	// Make sure the key is 2048 bits long
	pKey->put_Length(keyLength);

	// Create the key
	hr = pKey->Create();

	Common::LogIfError(hr, "Error creating private key");


	return hr;
}


void PrivateKey::Print()
{
	std::string keyLengthString;
	hr = GetLength(&keyLengthString);
	Common::LogIfError(hr, "Unable to get private key length");

	std::cout << "Private Key: [" << GetAlgorithmName() << " " << keyLengthString << " " << GetFriendlyName() << "]" << std::endl;
}

HRESULT PrivateKey::GetLength(std::string* outLength)
{
	LONG length;
	hr = pKey->get_Length(&length);

	if(hr == S_OK)
	{
		*outLength = std::to_string(length);
	}

	Common::LogIfError(hr, "Error getting private key length");

	return hr;
	
}

HRESULT PrivateKey::ExportPublicKey(IX509PublicKey** pPublicKey)
{
	hr = pKey->ExportPublicKey(pPublicKey);

	Common::LogIfError(hr, "Error exporting public key");

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

std::string PrivateKey::GetFriendlyName() const
{
	BSTR friendlyName;
	std::string result;
	if(pKey->get_FriendlyName(&friendlyName) == S_OK)	
	{			
		result = std::string(_bstr_t(friendlyName, true));
		SysFreeString(friendlyName);
	}
	else
	{
		result = "";
	}
	
	return result;
}


HRESULT PrivateKey::Uninitialize() const
{
	if (nullptr != pKey) pKey->Release();
	return hr;
}
