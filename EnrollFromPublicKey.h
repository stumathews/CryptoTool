#pragma once
#include <certenroll.h>
#include <certcli.h>
#include <wincrypt.h>

#include "CaConfig.h"
#include "CertificateRequester.h"
#include "CertificateRequestX509.h"
#include "CertificateRequestX509CMC.h"
#include "PrivateKey.h"

class EnrollFromPublicKey
{
public:
	~EnrollFromPublicKey();
	void Uninitialize();
	HRESULT Initialize();
	HRESULT Perform(PCWSTR pwszTemplateName, PCWSTR pwszFileOut, PCWSTR pwszSigningTemplateName);
	HRESULT RetrievePending(LONG requestId, const BSTR strConfig);

private:
	HRESULT hr {};
	bool fCoInit = false;
	CERT_CONTEXT const* pCert = nullptr;
	IX509PrivateKey* pKey = nullptr;
	PrivateKey privateKey;
	CertificateRequestX509 x509CertificateRequest;
	CertificateRequestX509CMC x509CmcCertificateRequest;
	CaConfig caConfig;
	IX509PublicKey* pPublicKey = nullptr;
	ISignerCertificate* pSignerCertificate = nullptr;
	ISignerCertificates* pSignerCertificates = nullptr;
	CertificateRequester certificateRequester;
	BSTR strTemplateName = nullptr;
	BSTR strCAConfig = nullptr;
	BSTR strCertificateRequest = nullptr;
	BSTR strRACert = nullptr;
	BSTR strDisposition = nullptr;
	VARIANT varFullResponse = {};
	LONG pDisposition = 0;
};


