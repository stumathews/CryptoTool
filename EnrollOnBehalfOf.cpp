#include "EnrollOnBehalfOf.h"

#include "CmcCertificateRequest.h"
#include "enrollCommon.h"


void EnrollOnBehalfOf::Initialize()
{
    // CoInitializeEx
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    _JumpIfError(hr, error, "CoInitializeEx");
    fCoInit = true;

    // Allocate BSTR for template name
    strTemplateName = SysAllocString(pwszTemplateName);
    if (NULL == strTemplateName)
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "SysAllocString");
    }

    // Allocate BSTR for requester name
    strRequester = SysAllocString(pwszRequester);
    if (NULL == strRequester)
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "SysAllocString");
    }

    // Allocate BSTR for the password of PFX file
    strPassword = SysAllocString(pwszPassword);
    if (NULL == strPassword)
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "SysAllocString");
    }
    error:
    ;
}

void EnrollOnBehalfOf::Uninitialize()
{
	SysFreeString(strTemplateName);
    SysFreeString(strRequester);
    SysFreeString(strEACert);
    SysFreeString(strCert);
    SysFreeString(strPFX);
    SysFreeString(strPassword);
    if (NULL != pEnroll) pEnroll->Release();
    if (NULL != pRequest) pRequest->Release();
    if (NULL != pInnerRequest) pInnerRequest->Release();
    if (NULL != pPkcs10) pPkcs10->Release();
    if (NULL != pCmc) pCmc->Release();
    if (NULL != pKey) pKey->Release();
    if (NULL != pSignerCertificate) pSignerCertificate->Release();
    if (NULL != pSignerCertificates) pSignerCertificates->Release();
    if (NULL != pCert) CertFreeCertificateContext(pCert);
    if (NULL != pCertContext) CertFreeCertificateContext(pCertContext);
    if (NULL != hStore) CertCloseStore(hStore, 0);
    if (fCoInit) CoUninitialize();
}

void EnrollOnBehalfOf::Perform(PCWSTR pwszTemplateName,  PCWSTR pwszRequester, PCWSTR pwszFileOut, PCWSTR pwszPassword, PCWSTR pwszEATemplateName = L"EnrollmentAgent")
{
    this->pwszTemplateName = pwszTemplateName;
    this->pwszRequester = pwszRequester;
    this->pwszFileOut = pwszFileOut;
	this->pwszPassword = pwszPassword;
    this->pwszEATemplateName = pwszEATemplateName;
      
    // Create IX509CertificateRequestCmc

    CmcCertificateRequest cmcCertificateRequest;
    cmcCertificateRequest.Initialize();
    pCmc = cmcCertificateRequest.GetRequest();

    // Initialize IX509CertificateRequestCmc
    hr = pCmc->InitializeFromTemplateName(
            ContextUser,      
            strTemplateName); 
    _JumpIfError(hr, error, "InitializeFromTemplateName");

    // Add requester name since it is an EOBO request
    hr = pCmc->put_RequesterName(strRequester);
    _JumpIfError(hr, error, "put_RequesterName");    
 
    /* Find a EA certificate first */

    // Find a cert that has EKU of Certificate Request Agent
    hr = findCertByEKU(szOID_ENROLLMENT_AGENT, &pCert);
    if (S_OK != hr) // Cert not found
    {
        // Enroll an EA cert first
        hr = enrollCertByTemplate(pwszEATemplateName);
        _JumpIfError(hr, error, "enrollCertByTemplate");    
 
        // Search again
        hr = findCertByEKU(szOID_ENROLLMENT_AGENT, &pCert);
        _JumpIfError(hr, error, "findCertByEKU");  
    }

    // Verify the certificate chain and its EKU
    hr = verifyCertContext(pCert, (char*)szOID_ENROLLMENT_AGENT);
    _JumpIfError(hr, error, "verifyCertContext");

    // Convert PCCERT_CONTEXT to BSTR
    strEACert = SysAllocStringByteLen(
            (CHAR const *) pCert->pbCertEncoded, 
            pCert->cbCertEncoded);

    if (NULL == strEACert)
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "SysAllocStringByteLen");
    }

    /* Sign the EOBO request with EA certificate */
    
     // Create ISignerCertificate
    hr = CoCreateInstance(
            __uuidof(CSignerCertificate),
            NULL,   // pUnkOuter
            CLSCTX_INPROC_SERVER, 
            __uuidof(ISignerCertificate), 
            (void **)&pSignerCertificate); 
   _JumpIfError(hr, error, "CoCreateInstance");

    // Initialize ISignerCertificate from EA certificate
    hr = pSignerCertificate->Initialize(
            VARIANT_FALSE,
            VerifyNone,
            XCN_CRYPT_STRING_BINARY,
            strEACert);
   _JumpIfError(hr, error, "Initialize");

    // Retrieve ISignerCertificates collection from CMC request
    hr = pCmc->get_SignerCertificates(&pSignerCertificates);
    _JumpIfError(hr, error, "get_SignerCertificates");

    // Add EA certificate into ISignerCertificates collection
    hr = pSignerCertificates->Add(pSignerCertificate);
    _JumpIfError(hr, error, "Add");


    /* Enroll for EOBO request */
    
    // Create IX509Enrollment
    hr = CoCreateInstance(
            __uuidof(CX509Enrollment),
            NULL,       // pUnkOuter
            CLSCTX_INPROC_SERVER,
            __uuidof(IX509Enrollment),
            (void **) &pEnroll);
    _JumpIfError(hr, error, "CoCreateInstance");

    // Initialize IX509Enrollment
    hr = pEnroll->InitializeFromRequest(pCmc);
    _JumpIfError(hr, error, "InitializeFromRequest");

    // Enroll
    hr = pEnroll->Enroll();
    _JumpIfError(hr, error, "Enroll");

    // Check enrollment status
    hr = checkEnrollStatus(pEnroll);
    _JumpIfError(hr, error, "checkEnrollStatus"); 


    /* Export the enrolled cert to a PFX file */

    // Create PFX output in binary format
    hr = pEnroll->CreatePFX(
            strPassword, 
            PFXExportEEOnly,
            XCN_CRYPT_STRING_BINARY, 
            &strPFX);
    _JumpIfError(hr, error, "checkEnrollStatus"); 

    // Save the PFX output to file in binary format
    hr = EncodeToFileW(
            pwszFileOut, 
            (BYTE const *) strPFX, 
            SysStringByteLen(strPFX), 
            CR_OUT_BINARY | DECF_FORCEOVERWRITE);
    _JumpIfError(hr, error, "EncodeToFileW");


    /* Retrieve and delete the enrolled cert from store */

    // Get the cert just enrolled in binary format
    hr = pEnroll->get_Certificate(XCN_CRYPT_STRING_BINARY, &strCert);
    _JumpIfError(hr, error, "get_Certificate"); 
    

    // Get the PCCERT_CONTEXT handle out of the certificate
    pCert = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            (BYTE const *)strCert,
            SysStringByteLen(strCert));

    if (NULL == pCert)
    {
        hr = GetLastError();
        _JumpError(hr, error, "CertCreateCertificateContext");
    }
    
    // Open user MY store
    hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            X509_ASN_ENCODING,
            NULL,
            CERT_SYSTEM_STORE_CURRENT_USER,
            L"MY"  );
    
    if (NULL == hStore)
    {
        hr = GetLastError();
        _JumpError(hr, error, "CertOpenStore");
    }

    // Search for the cert based on CERT_CONTEXT
    pCertContext = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_EXISTING,
            pCert,
            NULL);

    if (NULL == pCertContext)
    {
        hr = GetLastError();
        _JumpError(hr, error, "CertFindCertificateInStore");
    }

    // Delete the cert from store 
    if (!CertDeleteCertificateFromStore(pCertContext))
    {
        hr = GetLastError();
        _JumpError(hr, error, "CertDeleteCertificateFromStore");
    }
    

    /* Delete the private key as well */

    // Retrieve the request
    hr = pEnroll->get_Request(&pRequest);
    _JumpIfError(hr, error, "get_Request"); 

    // Get the innermost request
    hr = pRequest->GetInnerRequest(LevelInnermost, &pInnerRequest);
    _JumpIfError(hr, error, "GetInnerRequest"); 

    // QueryInterface for the pkcs10 request
    hr = pInnerRequest->QueryInterface(
            __uuidof(IX509CertificateRequestPkcs10),
            (VOID **)&pPkcs10);
    _JumpIfError(hr, error, "QueryInterface");

    // Get the private key
    hr = pPkcs10->get_PrivateKey(&pKey);
    _JumpIfError(hr, error, "get_PrivateKey");

    // Close the private key
    hr = pKey->Close();
    _JumpIfError(hr, error, "Close");

    // Delete the private key
    hr = pKey->Delete();
    _JumpIfError(hr, error, "Delete");

error:
    ;
}

EnrollOnBehalfOf::~EnrollOnBehalfOf()
{
	Uninitialize();
}
