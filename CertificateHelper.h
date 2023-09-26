#pragma once
#include "BStringHelper.h"

class CertificateHelper
{
public:
	static std::wstring GetIssuer(CERT_CONTEXT const* pCertContext);
	static std::string GetTemplateName(CERT_CONTEXT const* pCertContext);
	static std::wstring IdentifyCertificate(const CERT_CONTEXT* pCertOut);
	static std::wstring GetCertificateSubjectName(const CERT_CONTEXT* pCertContext);
};

