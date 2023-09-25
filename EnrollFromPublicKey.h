#pragma once
#include <certenroll.h>
#include <certcli.h>
#include <wincrypt.h>
#include "PrivateKey.h"

class EnrollFromPublicKey
{
private:
	HRESULT hr;
	bool fCoInit;
	CERT_CONTEXT const* pCert = nullptr;
	ICertConfig* pCertConfig = nullptr;
	IX509CertificateRequestPkcs10* pPkcs10 = nullptr;
	IX509CertificateRequestCmc* pCmc = nullptr;
	IX509PrivateKey* pKey = nullptr;
	PrivateKey privateKeyFactory;
	std::string keyLengthString;
	IX509PublicKey* pPublicKey = nullptr;
	ISignerCertificate* pSignerCertificate = nullptr;
	ISignerCertificates* pSignerCertificates = nullptr;
	ICertRequest2* pCertRequest2 = nullptr;
	BSTR strTemplateName = nullptr;
	BSTR strCAConfig = nullptr;
	BSTR strRequest = nullptr;
	BSTR strRACert = nullptr;
	BSTR strDisposition = nullptr;
	VARIANT varFullResponse;
	LONG pDisposition;
public:
	~EnrollFromPublicKey();
	HRESULT GetDefaultCA();
	void Uninitialize();
	HRESULT Initialize();
	HRESULT InitializeICertRequest2();
	HRESULT Perform(PCWSTR pwszTemplateName, PCWSTR pwszFileOut, PCWSTR pwszSigningTemplateName);
	HRESULT RetrievePending(LONG requestId, const BSTR strConfig);
};


