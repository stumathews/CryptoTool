#pragma once
#include "CertificateRequestX509.h"

class CertificateRequester
{
public:
	HRESULT Initialize();
	void Uninitialize();
	~CertificateRequester(){ Uninitialize(); }
	HRESULT Submit(BSTR bstr, BSTR strCaConfig, LONG* pDisposition);
	ICertRequest2* Get() const { return pCertRequest2; }
private:
	HRESULT hr {};
	ICertRequest2* pCertRequest2 = nullptr;
	bool initialized {};
};

