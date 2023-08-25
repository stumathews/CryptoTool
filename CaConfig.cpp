#include "CaConfig.h"

#include "ErrorManager.h"




HRESULT CaConfig::GetCaConfig(BSTR*  bstrConfig, LONG flags)
{
	ICertConfig2 * pConfig = nullptr;
   // BSTR  bstrConfig = nullptr; //Contains CA configuration name

	HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        printf("Failed CoInitializeEx - [%x]\n", hr);
        goto error;
    }

    // Create an instance of the CertConfig object.
    hr = CoCreateInstance( __uuidof(CCertConfig),
                           nullptr,
                           CLSCTX_INPROC_SERVER,
                           _uuidof(ICertConfig2),
                           (void **)&pConfig);
    if (FAILED(hr))
    {
        printf("Failed CoCreateInstance - pConfig [%x]\n", hr);
        goto error;
    }

    // Retrieve the default CA configuration string.
    hr = pConfig->GetConfig(flags, bstrConfig);
    if (FAILED(hr))
    {
        printf("Failed GetConfig - [%x]\n", hr);
        goto error;
    }

error:

    // Done processing.
    if (pConfig)
        pConfig->Release();



    CoUninitialize();
	return hr;
}