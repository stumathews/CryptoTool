#pragma once
#include <stdio.h>
#include <certenroll.h>
#include <certsrv.h>
#include <certcli.h>
#include <wincrypt.h>
#include "enrollCommon.h"

class EnrollFromPublicKey
{
public:
	HRESULT GetDefaultCA();
	static HRESULT Perform(PCWSTR pwszTemplateName, PCWSTR pwszFileOut, PCWSTR pwszSigningTemplateName);
};
