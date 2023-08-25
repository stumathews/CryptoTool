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
	static HRESULT GetCaConfig(BSTR* bstrConfig, LONG flags = CC_DEFAULTCONFIG);
	static HRESULT GetCaField(BSTR* bstrFieldName, BSTR* bstrFieldValue);
};

