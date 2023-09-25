#pragma once
#include <certenroll.h>

class CmcCertificateRequest
{
public:
	void Initialize();
	void Uninitialize();
	~CmcCertificateRequest();
	IX509CertificateRequestCmc* GetRequest();
private:
	HRESULT hr;
	IX509CertificateRequestCmc* pCmc = nullptr;
};

