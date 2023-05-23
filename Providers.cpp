#include "Providers.h"
#include "ErrorManager.h"
#include <iostream>

bool Providers::Initialize()
{
	HRESULT           hr = S_OK;

	// Initialize COM.
	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr))
	{
		ErrorManager::PrintErrorCodeMessage(GetLastError());
		return false;
	}
	return true;
}

Providers::~Providers()
{
	CoUninitialize();
}

void Providers::List()
{
	HRESULT           hr = S_OK;  // Return value
	
	CComPtr<ICspInformations>     pCSPs;   // Provider collection
	CComPtr<ICspInformation>      pCSP;    // Provider instgance

	long              lCount = 0;     // Count of providers
	CComBSTR          bstrName;            // Provider name
	VARIANT_BOOL      bLegacy;             // CryptoAPI or CNG

	// Create a collection of cryptographic providers.
	hr = CoCreateInstance(
		__uuidof(CCspInformations),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(ICspInformations),
		(void**)&pCSPs);
		if (FAILED(hr))
		{
			ErrorManager::PrintErrorCodeMessage(GetLastError());
			return;
		}

	// Add the providers installed on the computer.
	hr = pCSPs->AddAvailableCsps();
	if (FAILED(hr))
	{
		ErrorManager::PrintErrorCodeMessage(GetLastError());
		return;
	}

	// Retrieve the number of installed providers.
	hr = pCSPs->get_Count(&lCount);
	if (FAILED(hr))
	{
		ErrorManager::PrintErrorCodeMessage(GetLastError());
		return;
	}

	// Print the providers to the console. Print the
	// name and a value that specifies whether the 
	// CSP is a legacy or CNG provider.
	for (long i = 0; i < lCount; i++)
	{
		hr = pCSPs->get_ItemByIndex(i, &pCSP);
		if (FAILED(hr))
		{
			ErrorManager::PrintErrorCodeMessage(GetLastError());
			return;
		}

		hr = pCSP->get_Name(&bstrName);
		if (FAILED(hr))
		{
			ErrorManager::PrintErrorCodeMessage(GetLastError());
			return;
		}


		hr = pCSP->get_LegacyCsp(&bLegacy);
		if (FAILED(hr))
		{
			ErrorManager::PrintErrorCodeMessage(GetLastError());
			return;
		}

		if (VARIANT_TRUE == bLegacy)
			wprintf_s(L"%2d. Legacy: ", i);
		else
			wprintf_s(L"%2d. CNG: ", i);

		wprintf_s(L"%s\n", static_cast<wchar_t*>(bstrName.m_str));
		

		pCSP = nullptr;

	}
}


