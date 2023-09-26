#include "CertificateRequester.h"

#include "Common.h"

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
