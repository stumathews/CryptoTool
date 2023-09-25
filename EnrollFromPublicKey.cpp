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

#include <certsrv.h>
#include <iostream>
#include <comutil.h>
#include <string>
#include <winerror.h>

#include "enrollCommon.h"
#include "ErrorManager.h"
#include "PrivateKey.h"
#pragma comment(lib,"comsuppw.lib")


HRESULT EnrollFromPublicKey::Initialize()
{
	std::cout << "[CoInitializeEx]" << std::endl;
	// CoInitializeEx
	const auto result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	
	fCoInit = true;
	return result;
}



HRESULT EnrollFromPublicKey::Perform(PCWSTR pwszTemplateName, PCWSTR pwszFileOut, PCWSTR pwszSigningTemplateName)
{

	std::wcout << "Requesting a cert using template: " << pwszTemplateName
	<< "\n will try to write it out to: "
	<< pwszFileOut << " \nand will sign with cert called: "
	<< pwszSigningTemplateName << std::endl;

	Initialize();
   
	/* Get the public key */

	std::cout << "Create IX509PrivateKey" << std::endl;

	privateKeyFactory.Initialize();
	
	_JumpIfError(hr, error, "CoCreateInstance");

	std::cout << "Create the key" << std::endl;

	privateKeyFactory.Create(2048);

	_JumpIfError(hr, error, "Create");
	
	keyLengthString = privateKeyFactory.GetLength().Match(
		[](long error) {return  std::string("[Error fetching length]"); },
		[](std::string inLength) {return inLength;});

	std::cout << "Key length is: " << keyLengthString << std::endl;

	std::cout << "Private key using algorithm: " << privateKeyFactory.GetAlgorithmName() << std::endl;

	std::cout << "Export the public key" << std::endl;
	// Export the public key
	//hr = privateKeyFactory.ExportPublicKey(&pPublicKey);
	
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
	// Initialize from public key
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
		std::cout << "Enroll a signing cert first" << std::endl;
		hr = enrollCertByTemplate(pwszSigningTemplateName);
		_JumpIfError(hr, error, "enrollCertByTemplate");    
 
		// Search again
		std::cout << "Search again" << std::endl;
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

	std::cout << "Using strCaConfig: " << std::string(_bstr_t(strCAConfig, true)) << std::endl;

	// Initialize ICertRequest2
	hr = InitializeICertRequest2();	
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

			// Get the requestId
			LONG requestId = 0;
			pCertRequest2->GetRequestId(&requestId);

			std::cout << "RequstId: " << requestId << std::endl;

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
	return hr;
}

HRESULT EnrollFromPublicKey::InitializeICertRequest2()
{
	const auto result = CoCreateInstance(
		__uuidof(CCertRequest),
		nullptr,
		CLSCTX_INPROC_SERVER,
		__uuidof(ICertRequest2),
		(void**)&pCertRequest2);
	return result;
}

HRESULT EnrollFromPublicKey::RetrievePending(const LONG requestId, const BSTR strConfig)
{
	LONG disposition;

	Initialize();

	InitializeICertRequest2();

	if((hr = pCertRequest2->RetrievePending(requestId, strConfig, &disposition)) == S_OK)
	{
		if(disposition == CR_DISP_ISSUED)
		{
			std::cout << "Getting certificate..." << std::endl;
			BSTR  bstrCert = NULL;
			if(pCertRequest2->GetCertificate(CR_OUT_BASE64, &bstrCert) == S_OK)
			{
				const std::string certificate(_bstr_t(bstrCert, true));
				std::cout << certificate << std::endl;
				SysFreeString(bstrCert);
			}
			else
			{
				std::cout << "Failed to get certificate" << std::endl;
			}

			
		}
		else
		{
			std::cout << "Not Issued." << std::endl;
			/*LONG status;
			pCertRequest2->GetLastStatus(&status);
			hr = pCertRequest2->GetDispositionMessage(&strDisposition);*/
			
		}
	}
	else
	{
		std::cout << "Failed calling RetrievePending..." << std::endl;
		ErrorManager::PrintErrorCodeMessage(hr);
	}
	return hr;
}

EnrollFromPublicKey::~EnrollFromPublicKey()
{
	Uninitialize();
}

void EnrollFromPublicKey::Uninitialize()
{
	SysFreeString(strTemplateName);
	SysFreeString(strCAConfig);
	SysFreeString(strRequest);
	SysFreeString(strRACert);
	SysFreeString(strDisposition);
	VariantClear(&varFullResponse);
	
	privateKeyFactory.Uninitialize();

	if (nullptr != pPublicKey) pPublicKey->Release();
	if (nullptr != pPkcs10) pPkcs10->Release();
	if (nullptr != pCmc) pCmc->Release();
	if (nullptr != pCertRequest2) pCertRequest2->Release();
	if (nullptr != pSignerCertificate) pSignerCertificate->Release();
	if (nullptr != pSignerCertificates) pSignerCertificates->Release();
	if (nullptr != pCert) CertFreeCertificateContext(pCert);
	if (fCoInit) CoUninitialize();
}


