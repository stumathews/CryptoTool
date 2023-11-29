#pragma once
#include <xstring>

#include "CertificateRequestX509.h"

class CertificateRequester
{
public:
	HRESULT Initialize();
	void Uninitialize();
	HRESULT GetCaProperty(BSTR strCaConfig, LONG propId, LONG prodIndex, LONG propType, LONG flags,
	                      VARIANT* pvarPropertyValue);
	std::wstring GetCaTemplates(BSTR strCaConfig);
	~CertificateRequester(){ Uninitialize(); }
	HRESULT Submit(BSTR bstr, BSTR strCaConfig, LONG* pDisposition);
	ICertRequest2* Get() const { return pCertRequest2; }
private:
	HRESULT hr {};
	ICertRequest2* pCertRequest2 = nullptr;
	bool initialized {};
};

