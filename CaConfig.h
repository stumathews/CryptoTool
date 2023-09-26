#pragma once
#pragma once
#include <stdio.h>
#include <certenroll.h>
#include <certsrv.h>
#include <certcli.h>
#include <wincrypt.h>
#include "enrollCommon.h"

class CaConfig
{
public:
	HRESULT Initialize();
	void Uninitialize() const;
	HRESULT GetConfig(LONG flags, BSTR* bstrConfig);
	HRESULT GetConfig(BSTR* bstrConfig, LONG flags);
	~CaConfig() { Uninitialize(); }
	ICertConfig2 * Get() const { return pConfig;}
	static HRESULT GetCaConfig(BSTR* bstrConfig, LONG flags = CC_DEFAULTCONFIG);
	static HRESULT GetCaField(BSTR* bstrFieldName, BSTR* bstrFieldValue);
private:
	HRESULT hr {};
	ICertConfig2 * pConfig = nullptr;

};

