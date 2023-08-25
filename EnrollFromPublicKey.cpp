//---------------------------------------------------------------------
//  This file is part of the Microsoft .NET Framework SDK Code Samples.
// 
//  Copyright (C) Microsoft Corporation.  All rights reserved.
// 
//This source code is intended only as a supplement to Microsoft
//Development Tools and/or on-line documentation.  See these other
//materials for detailed information regarding Microsoft code samples.
// 
//THIS CODE AND INFORMATION ARE PROVIDED AS IS WITHOUT WARRANTY OF ANY
//KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
//PARTICULAR PURPOSE.
//---------------------------------------------------------------------

// Initialize a pkcs10 request from the public key, wrap it in 
// a CMC request, encode the CMC request, submit it to an 
// enterprise CA, and save the response to a file


#include "EnrollFromPublicKey.h"
#include <iostream>
#include <comutil.h>
#include <winerror.h>
#include "ErrorManager.h"
#pragma comment(lib,"comsuppw.lib")

HRESULT EnrollFromPublicKey::Perform(PCWSTR pwszTemplateName, PCWSTR pwszFileOut, PCWSTR pwszSigningTemplateName)
{
	HRESULT hr;
	bool fCoInit;
	CERT_CONTEXT const* pCert = nullptr;
	ICertConfig* pCertConfig = nullptr;
	IX509CertificateRequestPkcs10* pPkcs10 = nullptr;
	IX509CertificateRequestCmc* pCmc = nullptr;
	IX509PrivateKey* pKey = nullptr;
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

	std::cout << "[CoInitializeEx]" << std::endl;

	// CoInitializeEx
	hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	_JumpIfError(hr, error, "CoInitializeEx");
	fCoInit = true;
    
	/* Get the public key */

	std::cout << "Create IX509PrivateKey" << std::endl;
	// Create IX509PrivateKey
	hr = CoCreateInstance(
		__uuidof(CX509PrivateKey),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		__uuidof(IX509PrivateKey),
		(void **) &pKey);
	_JumpIfError(hr, error, "CoCreateInstance");

	std::cout << "Create the key" << std::endl;
	// Create the key
	hr = pKey->Create();
	_JumpIfError(hr, error, "Create");

	std::cout << "Export the public key" << std::endl;
	// Export the public key
	hr = pKey->ExportPublicKey(&pPublicKey);
	_JumpIfError(hr, error, "ExportPublicKey");
	
	std::cout << "Intilialize the CMC request from the public key" << std::endl;
	/* Intilialize the CMC request from the public key */

	// Create IX509CertificateRequestPkcs10
	hr = CoCreateInstance(
		__uuidof(CX509CertificateRequestPkcs10),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		__uuidof(IX509CertificateRequestPkcs10),
		(void **) &pPkcs10);
	_JumpIfError(hr, error, "CoCreateInstance");

	// Allocate BSTR for template name
	strTemplateName = SysAllocString(pwszTemplateName);
	if (nullptr == strTemplateName)
	{
		hr = E_OUTOFMEMORY;
		_JumpError(hr, error, "SysAllocString");
	}

	std::cout << "Initialize IX509CertificateRequestPkcs10 from public key" << std::endl;
	// Initialize IX509CertificateRequestPkcs10 from public key
	hr = pPkcs10->InitializeFromPublicKey(
		ContextUser,
		pPublicKey,
		strTemplateName);
	_JumpIfError(hr, error, "InitializeFromPublicKey");

	std::cout << "Create IX509CertificateRequestCmc" << std::endl;
	// Create IX509CertificateRequestCmc
	hr = CoCreateInstance(
		_uuidof(CX509CertificateRequestCmc),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		_uuidof(IX509CertificateRequestCmc),
		(void **) &pCmc);
	_JumpIfError(hr, error, "CoCreateInstance");

	// Initialize IX509CertificateRequestCmc
	hr = pCmc->InitializeFromInnerRequest(pPkcs10);
	_JumpIfError(hr, error, "InitializeFromInnerRequest");


	std::cout << "Sign the CMC request with a signing cert " << std::endl;
	/* Sign the CMC request with a signing cert */

	// Find a signing cert
	hr = findCertByKeyUsage(CERT_DIGITAL_SIGNATURE_KEY_USAGE, &pCert);
	if (S_OK != hr) // Cert not found
	{
		// Enroll a signing cert first
		hr = enrollCertByTemplate(pwszSigningTemplateName);
		_JumpIfError(hr, error, "enrollCertByTemplate");    
 
		// Search again
		hr = findCertByKeyUsage(CERT_DIGITAL_SIGNATURE_KEY_USAGE, &pCert);
		_JumpIfError(hr, error, "findCertByKeyUsage");  
	}

	std::cout << "Verify the certificate chain" << std::endl;
	// Verify the certificate chain
	hr = verifyCertContext(pCert, nullptr);
	_JumpIfError(hr, error, "verifyCertContext");

	// Convert PCCERT_CONTEXT to BSTR
	strRACert = SysAllocStringByteLen(
		(CHAR const *) pCert->pbCertEncoded, 
		pCert->cbCertEncoded);

	if (nullptr == strRACert)
	{
		hr = E_OUTOFMEMORY;
		_JumpError(hr, error, "SysAllocStringByteLen");
	}

	std::cout << "Retrieve ISignerCertificates collection from CMC request" << std::endl;
	// Retrieve ISignerCertificates collection from CMC request
	hr = pCmc->get_SignerCertificates(&pSignerCertificates);
	_JumpIfError(hr, error, "get_SignerCertificates");

	// Create ISignerCertificate
	hr = CoCreateInstance(
		__uuidof(CSignerCertificate),
		nullptr,   // pUnkOuter
		CLSCTX_INPROC_SERVER, 
		__uuidof(ISignerCertificate), 
		(void **)&pSignerCertificate); 
	_JumpIfError(hr, error, "CoCreateInstance");

	// Initialize ISignerCertificate from signing cert
	hr = pSignerCertificate->Initialize(
		VARIANT_FALSE,
		VerifyNone,
		XCN_CRYPT_STRING_BINARY,
		strRACert);
	_JumpIfError(hr, error, "Initialize");

	// Add the signing cert into ISignerCertificates collection
	hr = pSignerCertificates->Add(pSignerCertificate);
	_JumpIfError(hr, error, "Add");

	std::cout << "Encode the CMC request, submit the request to an enterprise CA" << std::endl;
	/* Encode the CMC request, submit the request to an enterprise CA */

	// Encode the CMC request
	hr = pCmc->Encode();
	_JumpIfError(hr, error, "Encode");
    
	// Get BSTR of the CMC request
	hr = pCmc->get_RawData(XCN_CRYPT_STRING_BASE64, &strRequest);
	_JumpIfError(hr, error, "Encode");

	// Create ICertConfig
	hr = CoCreateInstance(
		__uuidof(CCertConfig),
		nullptr,
		CLSCTX_INPROC_SERVER,
		__uuidof(ICertConfig),
		(void**)&pCertConfig);
	_JumpIfError(hr, error, "CoCreateInstance");

	std::cout << "Get the CA Config from UI" << std::endl;
	// Get the CA Config from UI
	hr = pCertConfig->GetConfig(CC_UIPICKCONFIG, &strCAConfig);
	_JumpIfError(hr, error, "GetConfig");

	// Initialize ICertRequest2
	hr = CoCreateInstance(
		__uuidof(CCertRequest),
		nullptr,
		CLSCTX_INPROC_SERVER,
		__uuidof(ICertRequest2),
		(void**)&pCertRequest2);
	_JumpIfError(hr, error, "CoCreateInstance");

	std::cout << "Submit the request" << std::endl;
	// Submit the request
	hr = pCertRequest2->Submit(
		CR_IN_BASE64 | CR_IN_FORMATANY, 
		strRequest,
		nullptr, 
		strCAConfig,
		&pDisposition);   
	_JumpIfError(hr, error, "Submit");

	// Check the submission status
	if (pDisposition != CR_DISP_ISSUED) // Not enrolled
	{
		hr = pCertRequest2->GetDispositionMessage(&strDisposition);
		_JumpIfError(hr, error, "GetDispositionMessage");
        
		if (pDisposition == CR_DISP_UNDER_SUBMISSION) // Pending
		{
			wprintf(L"The submission is pending: %ws\n", strDisposition);
			_JumpError(hr, error, "Submit");
		} 
		else // Failed
		{
			wprintf(L"The submission failed: %ws\n", strDisposition);
			pCertRequest2->GetLastStatus(&hr);
			_JumpError(hr, error, "Submit");
		}
	}

		std::cout << "Get the response, and save it to a file" << std::endl;
	/* Get the response, and save it to a file */

	// Initialize varFullResponse
	VariantInit(&varFullResponse);
	varFullResponse.vt = VT_BSTR;
	varFullResponse.bstrVal = nullptr;

	// Get the full response in binary format
	hr = pCertRequest2->GetFullResponseProperty(
		FR_PROP_FULLRESPONSENOPKCS7,
		0,
		PROPTYPE_BINARY,
		CR_OUT_BINARY,
		&varFullResponse);
	_JumpIfError(hr, error, "GetFullResponseProperty");

	// Save the response to file in base64 format
	hr = EncodeToFileW(
		pwszFileOut, 
		(BYTE const *) varFullResponse.bstrVal, 
		SysStringByteLen(varFullResponse.bstrVal), 
		CR_OUT_BASE64 | DECF_FORCEOVERWRITE);
	_JumpIfError(hr, error, "EncodeToFileW");

error:
	SysFreeString(strTemplateName);
	SysFreeString(strCAConfig);
	SysFreeString(strRequest);
	SysFreeString(strRACert);
	SysFreeString(strDisposition);
	VariantClear(&varFullResponse);
	if (nullptr != pKey) pKey->Release();
	if (nullptr != pPublicKey) pPublicKey->Release();
	if (nullptr != pPkcs10) pPkcs10->Release();
	if (nullptr != pCmc) pCmc->Release();
	if (nullptr != pCertRequest2) pCertRequest2->Release();
	if (nullptr != pSignerCertificate) pSignerCertificate->Release();
	if (nullptr != pSignerCertificates) pSignerCertificates->Release();
	if (nullptr != pCert) CertFreeCertificateContext(pCert);
	if (fCoInit) CoUninitialize();
	return hr;
}

//HRESULT __cdecl not_wmain(__in int argc, __in_ecount(argc) wchar_t *argv[])
//{
//
//    HRESULT hr = S_OK;
//    bool fCoInit = false;
//    PCWSTR pwszTemplateName;
//    PCWSTR pwszFileOut;
//    PCWSTR pwszSigningTemplateName = L"User";    
//    CERT_CONTEXT const *pCert = NULL;
//    ICertConfig* pCertConfig = NULL;
//    IX509CertificateRequestPkcs10* pPkcs10 = NULL;
//    IX509CertificateRequestCmc* pCmc = NULL;
//    IX509PrivateKey* pKey = NULL;
//    IX509PublicKey* pPublicKey = NULL;
//    ISignerCertificate* pSignerCertificate = NULL;
//    ISignerCertificates* pSignerCertificates = NULL;
//    ICertRequest2* pCertRequest2 = NULL;
//    BSTR strTemplateName = NULL;
//    BSTR strCAConfig = NULL;
//    BSTR strRequest = NULL;
//    BSTR strRACert = NULL;
//    BSTR strDisposition = NULL;
//    VARIANT varFullResponse;
//    LONG pDisposition = 0;
//
//    // Process command line arguments
//    if (argc !=  3 && argc !=  4) {
//        Usage();
//        hr = E_INVALIDARG;
//        _JumpError(hr, error, "invalid arg");
//    }
//    else
//    {
//        pwszTemplateName = argv[1];
//        pwszFileOut = argv[2];
//        if (argc == 4)
//            pwszSigningTemplateName = argv[3];
//    }
//
//    return EnrollFromPublicKey(pwszTemplateName, pwszFileOut, pwszSigningTemplateName);
//}
//
