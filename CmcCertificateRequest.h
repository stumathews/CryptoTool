#pragma once
#include <certenroll.h>

class CmcCertificateRequest
{
public:
	HRESULT Initialize();
	void Uninitialize();
	~CmcCertificateRequest();
	IX509CertificateRequestCmc* GetRequest() const;
private:
	HRESULT hr;
	IX509CertificateRequestCmc* pCmc = nullptr;
};

