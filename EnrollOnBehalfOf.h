#pragma once
#include "CaConfig.h"

class EnrollOnBehalfOf
{
public:

	void Uninitialize() const;
    void Perform(PCWSTR pwszTemplateName, PCWSTR pwszRequester, PCWSTR pwszFileOut, PCWSTR pwszPassword, PCWSTR pwszEATemplateName);
    ~EnrollOnBehalfOf();
private:
	HRESULT hr = S_OK;
    void Initialize(PCWSTR pwszTemplateName, PCWSTR pwszRequester, PCWSTR pwszFileOut, PCWSTR pwszPassword, PCWSTR pwszEATemplateName);
    bool fCoInit = false;
    IX509Enrollment* pEnroll = nullptr; 
    IX509CertificateRequest* pRequest = nullptr;
    IX509CertificateRequest* pInnerRequest = nullptr;
    IX509CertificateRequestPkcs10* pPkcs10 = nullptr;
    IX509CertificateRequestCmc* pCmc = nullptr;
    IX509PrivateKey *pKey = nullptr;
    ISignerCertificate* pSignerCertificate = nullptr;
    ISignerCertificates* pSignerCertificates = nullptr;
    HCERTSTORE hStore = nullptr;
    CERT_CONTEXT const *pCert = nullptr;
    CERT_CONTEXT const *pCertContext = nullptr;
    PCWSTR pwszTemplateName = nullptr; //
    PCWSTR pwszRequester = nullptr;
    PCWSTR pwszFileOut = nullptr;
    PCWSTR pwszPassword = nullptr;
    PCWSTR pwszEATemplateName = L"EnrollmentAgent";
    BSTR strTemplateName = nullptr;
    BSTR strRequester = nullptr;
    BSTR strEACert = nullptr;
    BSTR strCert = nullptr;
    BSTR strPFX = nullptr;
    BSTR strPassword = nullptr;
};

