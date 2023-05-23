#pragma once
#include <strsafe.h>
#include <combaseapi.h>
#include <atlcomcli.h>
#include <certenroll.h>

#include "ErrorManager.h"

class Providers
{
public:
	static bool Initialize();

	~Providers();
	static void List();
};