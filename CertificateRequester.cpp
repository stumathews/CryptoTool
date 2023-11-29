#include "CertificateRequester.h"

#include <certsrv.h>

#include "Common.h"
#include "Propvarutil.h"

#pragma comment(lib, "Propsys")

HRESULT CertificateRequester::Initialize()
{
	if(initialized)
	{
		return S_OK;
	}

	hr = CoCreateInstance(
		__uuidof(CCertRequest),
		nullptr,
		CLSCTX_INPROC_SERVER,
		__uuidof(ICertRequest2),
		(void**)&pCertRequest2);

	Common::LogIfError(hr, "Error creating CCertRequest");

	if(hr == S_OK) { initialized = true;}

	return hr;
}



void CertificateRequester::Uninitialize()
{
	if (nullptr != pCertRequest2) pCertRequest2->Release();

	if(initialized)
	{
		initialized = false;
	}
}

HRESULT CertificateRequester::GetCaProperty(const BSTR strCaConfig, const LONG propId, const LONG prodIndex,
                                            const LONG propType, const LONG flags, VARIANT* pvarPropertyValue)
{
	hr = this->pCertRequest2->GetCAProperty(strCaConfig, propId, prodIndex, propType, flags, pvarPropertyValue);
	Common::LogIfError(hr, "Error fetching CA property");
	return hr;
}

std::wstring CertificateRequester::GetCaTemplates(BSTR strCaConfig)
{
	WCHAR buffer[4096];
	VARIANT propertyValue;
	VariantInit(&propertyValue);
	hr = GetCaProperty(strCaConfig, CR_PROP_TEMPLATES, 0, PROPTYPE_STRING, 0, &propertyValue);
	Common::LogIfError(hr, "Error fetching CA certificate templates");
	
	VariantToString(propertyValue, buffer, 4096 );
	std::wstring templates = buffer;
	
	 VariantClear(&propertyValue);
	return templates;
}

HRESULT CertificateRequester::Submit(const BSTR strCertificateRequest, const BSTR strCAConfig, LONG* pDisposition)
{
	// Submit the request
	hr = pCertRequest2->Submit(
		CR_IN_BASE64 | CR_IN_FORMATANY, 
		strCertificateRequest,
		nullptr, 
		strCAConfig,
		pDisposition);

	Common::LogIfError(hr, "Error submitting certificate request");

	return hr;
}
