#include "CertificateRequestX509.h"

#include "Common.h"

DWORD CertificateRequestX509::Initialize(X509CertificateEnrollmentContext context, BSTR templateName)
{
// Create IX509CertificateRequestPkcs10
	hr = CoCreateInstance(
		__uuidof(CX509CertificateRequestPkcs10),
		nullptr,       // pUnkOuter
		CLSCTX_INPROC_SERVER,
		__uuidof(IX509CertificateRequestPkcs10),
		(void **) &pPkcs10);

	Common::LogIfError(hr, "Failed to create IX509CertificateRequestPkcs10");

	Context = context;
	TemplateName = templateName;

	return hr;
}

DWORD CertificateRequestX509::InitializeFromPublicKey(IX509PublicKey* pPublicKey)
{
	hr = pPkcs10->InitializeFromPublicKey(Context, pPublicKey, TemplateName);
	Common::LogIfError(hr, "Error initializing certificate request from public key");
	return hr;
}

HRESULT CertificateRequestX509::InitializeFromPrivateKey(IX509PrivateKey* privateKey)
{
	hr = pPkcs10->InitializeFromPrivateKey(Context, privateKey, TemplateName);
	Common::LogIfError(hr, "Error initializing certificate request from private key");
	return hr;
}

void CertificateRequestX509::Uninitialize() const
{
	if (nullptr != pPkcs10) pPkcs10->Release();
}

CertificateRequestX509::~CertificateRequestX509()
{
	Uninitialize();
}
