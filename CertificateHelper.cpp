#include "CertificateHelper.h"

#include "Common.h"

std::wstring CertificateHelper::GetIssuer(CERT_CONTEXT const* pCertContext)
{
    LPTSTR pszString;
    LPTSTR pszName;
    DWORD cbSize;
    std::wstring issuer {};

	if(!(cbSize = CertGetNameString(   
            pCertContext,   
            CERT_NAME_SIMPLE_DISPLAY_TYPE,   
            CERT_NAME_ISSUER_FLAG,
            nullptr,
            nullptr,   
            0)))
        {
            return issuer;
        }

        if(!(pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR))))
        {
            return issuer;
        }

        if(CertGetNameString(   
            pCertContext,   
            CERT_NAME_SIMPLE_DISPLAY_TYPE,   
            CERT_NAME_ISSUER_FLAG,
            nullptr,   
            pszName,   
            cbSize))
        {
            issuer = pszName;
            free(pszName);
        }

    return issuer;
}

std::string CertificateHelper::GetTemplateName(CERT_CONTEXT const* pCertContext)
{
    BYTE               *pbDecoded;
    DWORD               cbDecoded;
    std::string foundTemplateName = "<Template name not found>";

    for (int i = 0; i < pCertContext->pCertInfo->cExtension; i++)
    {
        if (CryptDecodeObject(
            X509_ASN_ENCODING,
            pCertContext->pCertInfo->rgExtension[i].pszObjId,
            pCertContext->pCertInfo->rgExtension[i].Value.pbData,
            pCertContext->pCertInfo->rgExtension[i].Value.cbData,
            0,
            nullptr,
            &cbDecoded))
        {
            Common::LogIfError(0, "Error decoding certificate extended data");
        }

        if (!(pbDecoded = static_cast<BYTE*>(malloc(cbDecoded))))
        {
            Common::LogIfError(0, "Error allocating memory for decoded certificate extended data");
        }

        if (CryptDecodeObject(
            X509_ASN_ENCODING,
            pCertContext->pCertInfo->rgExtension[i].pszObjId,
            pCertContext->pCertInfo->rgExtension[i].Value.pbData,
            pCertContext->pCertInfo->rgExtension[i].Value.cbData,
            0,
            pbDecoded,
            &cbDecoded))
        {
            const _CERT_TEMPLATE_EXT* pbDecodedTemplate = reinterpret_cast<_CERT_TEMPLATE_EXT*>(pbDecoded);

            foundTemplateName = pbDecodedTemplate->pszObjId;
        }
    }

    return foundTemplateName;
}

std::wstring CertificateHelper::IdentifyCertificate(const CERT_CONTEXT* pCertContext)
{
    return std::wstring(L"[") + 
			std::wstring(L"SubjectName: ") + GetCertificateSubjectName(pCertContext) + std::wstring(L" Issuer: ") + GetIssuer(pCertContext)
			+ std::wstring(L" ]");
}

std::wstring CertificateHelper::GetCertificateSubjectName(const CERT_CONTEXT* pCertContext)
{
        LPTSTR pszName;
        DWORD cbSize;
		std::wstring subject {};

        if(!(cbSize = CertGetNameString(   
            pCertContext,   
            CERT_NAME_SIMPLE_DISPLAY_TYPE,   
            0,
            NULL,   
            NULL,   
            0)))
        {
            return subject;
        }

        if(!(pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR))))
        {
            return subject;
        }

        if(CertGetNameString(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            pszName,
            cbSize))

        {
            subject = std::wstring(pszName);
            free(pszName);
        }

    return subject;
}
