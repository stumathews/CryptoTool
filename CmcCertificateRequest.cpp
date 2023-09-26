#include "CmcCertificateRequest.h"

#include <certenroll.h>
#include <iostream>
#include <ostream>

void CmcCertificateRequest::Initialize()
{
	std::cout << "Create IX509CertificateRequestCmc" << std::endl;
	// Create IX509CertificateRequestCmc
	hr = CoCreateInstance(
		_uuidof(CX509CertificateRequestCmc),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		_uuidof(IX509CertificateRequestCmc),
		(void **) &pCmc);

}

void CmcCertificateRequest::Uninitialize()
{
	if (nullptr != pCmc) pCmc->Release();
}

CmcCertificateRequest::~CmcCertificateRequest()
{
	Uninitialize();
}

IX509CertificateRequestCmc* CmcCertificateRequest::GetRequest()
{
	return pCmc;
}
