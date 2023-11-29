#include "CmcCertificateRequest.h"

#include <certenroll.h>
#include <iostream>
#include <ostream>

#include "Common.h"

HRESULT CmcCertificateRequest::Initialize()
{
	
	// Create IX509CertificateRequestCmc
	hr = CoCreateInstance(
		_uuidof(CX509CertificateRequestCmc),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		_uuidof(IX509CertificateRequestCmc),
		(void **) &pCmc);

	Common::LogIfError(hr, "Error creating CX509CertificateRequestCmc");

	return hr;

}

void CmcCertificateRequest::Uninitialize()
{
	if (nullptr != pCmc) pCmc->Release();
}

CmcCertificateRequest::~CmcCertificateRequest()
{
	Uninitialize();
}

IX509CertificateRequestCmc* CmcCertificateRequest::GetRequest() const
{
	return pCmc;
}
