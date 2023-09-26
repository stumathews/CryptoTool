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
#include <fstream>
#include <string>
#include <winerror.h>

#include "BStringHelper.h"
#include "CertificateHelper.h"
#include "Common.h"
#include "enrollCommon.h"
#include "ErrorManager.h"
#include "PrivateKey.h"
#pragma comment(lib,"comsuppw.lib")


HRESULT EnrollFromPublicKey::Initialize()
{
	// CoInitializeEx
	hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

	Common::LogIfError(hr, "Error calling CoInitializeEx");
	
	fCoInit = true;
	return hr;
}

HRESULT EnrollFromPublicKey::Perform(PCWSTR pwszTemplateName, PCWSTR pwszFileOut, PCWSTR pwszSigningTemplateName)
{
	std::wcout << "Requesting a cert using template: " << pwszTemplateName << std::endl;
	std::wcout << "Sign with certificate with template of: " << pwszSigningTemplateName << std::endl;

	strTemplateName = BStringHelper::CreateBSTR(pwszTemplateName);

	Initialize();

	// Create a private key
	privateKey.Initialize();
	privateKey.Create(2048);

	privateKey.Print();

	// Get public key
	hr = privateKey.ExportPublicKey(&pPublicKey);

	// Create certificate request
	x509CertificateRequest.Initialize(ContextUser, strTemplateName);
	x509CertificateRequest.InitializeFromPublicKey(pPublicKey);

	// Create encrypted CMC certificate request and embed certificate request within
	x509CmcCertificateRequest.Initialize();
	hr = x509CmcCertificateRequest.Get()->InitializeFromInnerRequest(x509CertificateRequest.Get());
	
	// Find or Enroll a signing Certificate to use to sign certificate request
	if (S_OK != findCertByTemplate(pwszSigningTemplateName, &pCert))
	{
		hr = findCertByKeyUsage(CERT_DIGITAL_SIGNATURE_KEY_USAGE, &pCert);
	}

	if (S_OK != hr) // Cert not found
	{
		std::cout << "No signing certificate found to sign certificate request." << std::endl;
		std::wcout << "Enrolling new signing certificate (" << pwszSigningTemplateName << ")" << std::endl;

		hr = enrollCertByTemplate(pwszSigningTemplateName);

		Common::LogIfError(hr, "Error enrolling certificate by template");  
 
		// Search again
		hr = findCertByKeyUsage(CERT_DIGITAL_SIGNATURE_KEY_USAGE, &pCert);

		Common::LogIfError(hr, "Error finding certificate by key usage");  
	}
		
	std::wcout << "Will be using this signing certificate: " << CertificateHelper::IdentifyCertificate(pCert)  << std::endl; 

	// Verify the signing certificate chain
	hr = verifyCertContext(pCert, nullptr);

	Common::LogIfError(hr, "Problem encountered while verifying signing certificate context");

	// Sign the CMC request with a signing cert
	hr = x509CmcCertificateRequest.AddSigningCertificate(pCert);
	
	// Encode the CMC request
	hr = x509CmcCertificateRequest.Get()->Encode();

	Common::LogIfError(hr, "Problem encountered while encoding CMC request");
    
	// Get and encode raw CMC request
	hr = x509CmcCertificateRequest.Get()->get_RawData(XCN_CRYPT_STRING_BASE64, &strCertificateRequest);

	Common::LogIfError(hr, "Problem encountered while getting encoding CMC request");

	// Select CA to send request to
	hr = caConfig.Initialize();
	hr = caConfig.GetConfig(CC_UIPICKCONFIG, &strCAConfig);

	Common::LogIfError(hr, "Problem encountered while getting CA configuration");

	std::cout << "Using CA: " << std::string(_bstr_t(strCAConfig, true)) << std::endl;

	certificateRequester.Initialize();

	// Submit the request to an enterprise CA	
	hr = certificateRequester.Submit(strCertificateRequest, strCAConfig, &pDisposition);
	
	// Check the submission status
	if (pDisposition != CR_DISP_ISSUED) // Not enrolled
	{
		hr = certificateRequester.Get()->GetDispositionMessage(&strDisposition);
		
		Common::LogIfError(hr, "Problem encountered while getting disposition message");
        
		if (pDisposition == CR_DISP_UNDER_SUBMISSION) // Pending
		{
			wprintf(L"The submission is pending: %ws\n", strDisposition);
			
			LONG requestId = 0;
			certificateRequester.Get()->GetRequestId(&requestId);

			std::cout << "RequestId: " << requestId << std::endl;

			Common::LogIfError(hr, "Problem encountered while submitting certificate request");
			return hr;
		}

		wprintf(L"The submission failed: %ws\n", strDisposition);
		certificateRequester.Get()->GetLastStatus(&hr);

		Common::LogIfError(hr, "Problem encountered while submitting certificate request");

		return hr;
	}

	/* Get the response, and save it to a file */

	// Initialize varFullResponse
	VariantInit(&varFullResponse);
	varFullResponse.vt = VT_BSTR;
	varFullResponse.bstrVal = nullptr;

	// Get the full response in binary format
	hr = certificateRequester.Get()->GetFullResponseProperty(
		FR_PROP_FULLRESPONSENOPKCS7,
		0,
		PROPTYPE_BINARY,
		CR_OUT_BINARY,
		&varFullResponse);

	Common::LogIfError(hr, "Problem encountered while getting full response property");

	// Save the response to file in base64 format
	hr = EncodeToFileW(pwszFileOut,  reinterpret_cast<BYTE const*>(varFullResponse.bstrVal),  
		SysStringByteLen(varFullResponse.bstrVal), 
		CR_OUT_BASE64 | DECF_FORCEOVERWRITE);

	Common::LogIfError(hr, "Problem encountered while writing response to file");

	return hr;
}

HRESULT EnrollFromPublicKey::RetrievePending(const LONG requestId, const BSTR strConfig)
{
	LONG disposition;

	Initialize();

	certificateRequester.Initialize();

	if((hr = certificateRequester.Get()->RetrievePending(requestId, strConfig, &disposition)) == S_OK)
	{
		if(disposition == CR_DISP_ISSUED)
		{
			std::cout << "Certificate issued. Getting certificate..." << std::endl;
			BSTR  bstrCert = nullptr;

			if(certificateRequester.Get()->GetCertificate(CR_OUT_BASE64HEADER, &bstrCert) == S_OK)
			{
				const std::string certificate(_bstr_t(bstrCert, true));
				
				auto fileName =  L"base64x509.cer";

				// open the file
				const HANDLE hFile = CreateFile(fileName, GENERIC_WRITE, 0, nullptr,
				                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
				DWORD dwBytes = 0;
				const DWORD dwLen = ::SysStringLen( bstrCert ) * 2;

				if(WriteFile(hFile, bstrCert, dwLen, &dwBytes, nullptr))
				{
					std::wcout << "Saved to " << fileName << std::endl;
				}

				SysFreeString(bstrCert);
			}
			else
			{
				std::cout << "Failed to get certificate." << std::endl;
			}			
		}
		else
		{
			std::cout << "Not Issued." << std::endl;			
		}
	}
	else
	{
		std::cout << "Failed retrieving certificate from CA." << std::endl;
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
	SysFreeString(strCertificateRequest);
	SysFreeString(strRACert);
	SysFreeString(strDisposition);
	VariantClear(&varFullResponse);
	
	privateKey.Uninitialize();
	x509CertificateRequest.Uninitialize();
	x509CmcCertificateRequest.UnInitialize();

	if (nullptr != pPublicKey) pPublicKey->Release();
	if (nullptr != pCert) CertFreeCertificateContext(pCert);

	if (fCoInit) CoUninitialize();
}


