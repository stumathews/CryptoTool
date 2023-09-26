#pragma once
#include "CertificateRequestX509.h"

class CertificateRequestX509CMC
{
public:
	HRESULT Initialize();
	void UnInitialize() const;
	~CertificateRequestX509CMC(){ UnInitialize(); }
	IX509CertificateRequestCmc* Get() const { return pCmc; }
	HRESULT AddSigningCertificate(const CERT_CONTEXT* pCert);

private:
	HRESULT hr {};
	IX509CertificateRequestCmc* pCmc = nullptr;
	BSTR strRACert = nullptr;
		
	ISignerCertificate* pSignerCertificate = nullptr;

	// Collection for signing certificates
	ISignerCertificates* pSignerCertificates = nullptr;
};

