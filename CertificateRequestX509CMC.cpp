#include "CertificateRequestX509CMC.h"

#include "Common.h"

HRESULT CertificateRequestX509CMC::Initialize()
{
	hr = CoCreateInstance(
		_uuidof(CX509CertificateRequestCmc),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		_uuidof(IX509CertificateRequestCmc),
		(void **) &pCmc);

	Common::LogIfError(hr, "Could not initialize CX509CertificateRequestCmc");

	return hr;
}

void CertificateRequestX509CMC::UnInitialize() const
{
	if (nullptr != pCmc) pCmc->Release();
	if (nullptr != pSignerCertificate) pSignerCertificate->Release();
	if (nullptr != pSignerCertificates) pSignerCertificates->Release();
}

HRESULT CertificateRequestX509CMC::AddSigningCertificate(const CERT_CONTEXT* pCert)
{
	// Retrieve ISignerCertificates collection from CMC request
	hr = pCmc->get_SignerCertificates(&pSignerCertificates);
	Common::LogIfError(hr, "Error calling get_SignerCertificates on Cmc certificate request");

	// Create ISignerCertificate
	hr = CoCreateInstance(
		__uuidof(CSignerCertificate),
		nullptr,   // pUnkOuter
		CLSCTX_INPROC_SERVER, 
		__uuidof(ISignerCertificate), 
		(void **)&pSignerCertificate); 


	Common::LogIfError(hr, "Error creating ISignerCertificate");

	// Convert PCCERT_CONTEXT to BSTR
	strRACert = SysAllocStringByteLen((CHAR const *) pCert->pbCertEncoded, pCert->cbCertEncoded);

	if (nullptr == strRACert)
	{
		hr = E_OUTOFMEMORY;
		Common::LogIfError(hr, "Error allocating data for signing certificate");
	}

	// Initialize ISignerCertificate from signing cert
	hr = pSignerCertificate->Initialize(
		VARIANT_FALSE,
		VerifyNone,
		XCN_CRYPT_STRING_BINARY,
		strRACert);

	Common::LogIfError(hr, "Error initializing ISignerCertificate");

	// Add the signing cert into ISignerCertificates collection
	hr = pSignerCertificates->Add(pSignerCertificate);

	Common::LogIfError(hr, "Error adding ISignerCertificate to collection of signing certificates");

	return hr;
}
