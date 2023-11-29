#pragma once
#include "CmcCertificateRequest.h"

class CertificateRequestX509
{
public:
	DWORD Initialize(X509CertificateEnrollmentContext context, BSTR templateName);
	IX509CertificateRequestPkcs10* Get() const { return pPkcs10; }
	DWORD InitializeFromPublicKey(IX509PublicKey *pPublicKey);
	HRESULT InitializeFromPrivateKey(IX509PrivateKey* privateKey);
	void Uninitialize() const;
	~CertificateRequestX509();
private:
		IX509CertificateRequestPkcs10* pPkcs10 = nullptr;
		DWORD hr  {};
		X509CertificateEnrollmentContext Context {};
		BSTR TemplateName = nullptr;
};

