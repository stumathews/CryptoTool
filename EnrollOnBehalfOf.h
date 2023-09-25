#pragma once
#include "CaConfig.h"

class EnrollOnBehalfOf
{
public:
	void Initialize();
	void Uninitialize();
    void Perform(PCWSTR pwszTemplateName, PCWSTR pwszRequester, PCWSTR pwszFileOut, PCWSTR pwszPassword, PCWSTR pwszEATemplateName);
    ~EnrollOnBehalfOf();
	private:
	HRESULT hr = S_OK;
    bool fCoInit = false;
    IX509Enrollment* pEnroll = NULL; 
    IX509CertificateRequest* pRequest = NULL;
    IX509CertificateRequest* pInnerRequest = NULL;
    IX509CertificateRequestPkcs10* pPkcs10 = NULL;
    IX509CertificateRequestCmc* pCmc = NULL;
    IX509PrivateKey *pKey = NULL;
    ISignerCertificate* pSignerCertificate = NULL;
    ISignerCertificates* pSignerCertificates = NULL;
    HCERTSTORE hStore = NULL;
    CERT_CONTEXT const *pCert = NULL;
    CERT_CONTEXT const *pCertContext = NULL;
    PCWSTR pwszTemplateName; //
    PCWSTR pwszRequester;
    PCWSTR pwszFileOut;
    PCWSTR pwszPassword;
    PCWSTR pwszEATemplateName = L"EnrollmentAgent";
    BSTR strTemplateName = NULL;
    BSTR strRequester = NULL;
    BSTR strEACert = NULL;
    BSTR strCert = NULL;
    BSTR strPFX = NULL;
    BSTR strPassword = NULL;
};

