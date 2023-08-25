// CryptoTool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Ncrypt.lib")
#pragma comment(lib,"comsuppw.lib")

#include <vector>
#include <Windows.h>

#include "Provider.h"
#include "Providers.h"
#include <iostream>
#include <string>
#include <cwctype>

#include "CaConfig.h"
#include "EnrollFromPublicKey.h"
#include "Key.h"
#include <comutil.h>


bool IsEqual(const TCHAR* one, const TCHAR* two)
{
	return (_wcsicmp(one, two) == 0);
}

bool IsNumber(const std::wstring& s)
{
    return !s.empty() && std::find_if(s.begin(), 
        s.end(), [](wchar_t c) { return !std::iswdigit(c); }) == s.end();
}


void PrintUsage(const int totalArgs, const std::wstring command = L"")
{
	
	if(command.empty())
	{
		std::cout << std::endl
		      << "CryptTool.exe <Command> <Options>" << std::endl << std::endl
		      << "Commands: " << std::endl << std::endl
	          << "Provider: Perform operations on a specific provider" << std::endl
		      << "Providers: Perform operations on all providers" << std::endl
		      << "Key: Perform operations on a specified key" << std::endl
		      << "Certificate: Perform certificate operations" << std::endl << std::endl;
		return;
	}

	if(IsEqual(command.c_str(), L"Providers"))
	{
		std::cout << "CryptTool.exe Providers [-List]" << std::endl;
	}
	else if(IsEqual(command.c_str(), L"Provider"))
	{
		std::cout << "CryptTool.exe Provider -Name <ProviderName> -ListKeys" << std::endl;
		std::cout << "CryptoTool.exe Provider -Name <ProviderName> -CreateKey -Name MyKey -Exportable <true|false> -IsMachineWide <true|false> \
		-KeyLength 2048 -OverwriteIfExists <true|false> [-Algorithm -Name <AlgorithmName>]" << std::endl;
		std::cout << "CryptTool.exe Provider -Name <ProviderName> -DeleteKey -Name <KeyName>" << std::endl;
		std::cout << "CryptoTool.exe Provider -Name <ProviderName> -GetProperty <NCRYPT_NAME_PROPERTY>" << std::endl;
	}
	else if(IsEqual(command.c_str(), L"Key"))
	{
		std::cout << "CryptoTool.exe Key -Name <KeyName> -ProviderName <ProviderName> -GetProperty <NCRYPT_NAME_PROPERTY>" << std::endl;
	}
	else if(IsEqual(command.c_str(), L"CertificateAuthority"))
	{
		std::cout << "CryptoTool.exe CertificateAuthority -GetDefault" << std::endl;
		std::cout << "CryptoTool.exe CertificateAuthority -Select" << std::endl;

	}
	else
	{
		std::wcout << L"Unknown command: " << command.c_str() << std::endl;
	}	
}

bool HasAtLeastNumArgs(const int requiredNumArgs, const int totalArgs, const std::wstring command)  // NOLINT(performance-unnecessary-value-param)
{
	if(totalArgs >= requiredNumArgs)
	{
		return true;
	}
	
	PrintUsage(totalArgs, command);
	return false;
}

DWORD __cdecl wmain(_In_ int argc, _In_reads_(argc)LPWSTR  argv[])
{
	// CryptoTool.exe Providers List
	// CryptoTool.exe Provider -Name "ProviderName" -ListKeys

	const auto totalArgs = argc-1;
	std::vector<std::wstring> cmdArgs;

	for(int i = 0; i < argc;i++) { cmdArgs.emplace_back(argv[i]); }	

	if(!HasAtLeastNumArgs(1, totalArgs, L"")) return -1;

	const auto firstArg = cmdArgs[1].c_str();
	const auto command = firstArg;

	// Parse commands:
	if(IsEqual(command, L"Providers"))
	{
		if(!HasAtLeastNumArgs(2, totalArgs, command)) return -1;

		const auto secondArg =  cmdArgs[2].c_str();

		if(IsEqual(secondArg, L"-List"))
		{
			Providers::Initialize();
			Providers::List();
			return 0; //Finished
		}
	}
	else if (IsEqual(command, L"Provider"))
	{
		if(!HasAtLeastNumArgs(2, totalArgs, command)) return -1;

		const auto secondArg =  cmdArgs[2].c_str();

		if(IsEqual(secondArg, L"-Name"))
		{
			if(!HasAtLeastNumArgs(4, totalArgs, command)) return -1;

			const auto thirdArg =  cmdArgs[3].c_str();
			const auto fourthArg =  cmdArgs[4].c_str();
			
			const auto providerOperation = fourthArg;
			const auto providerName = thirdArg;

			Provider keyStorageProvider(providerName);
			keyStorageProvider.Open();


			// CryptoTool.exe Provider -Name "ProviderName" -ListKeys
			if(IsEqual(providerOperation, L"-ListKeys"))
			{				
				keyStorageProvider.EnumProviderKeys();
				return 0; // Finished 
			}

			// CryptoTool.exe Provider -Name "ProviderName" -GetProperty <NCRYPT_NAME_PROPERTY>
			if(IsEqual(providerOperation, L"-GetProperty"))
			{
				if(!HasAtLeastNumArgs(5, totalArgs, command)) return -1;

				const auto propertyName = cmdArgs[5];

				std::wcout << keyStorageProvider.GetProperty(propertyName, 0, 0, false) << std::endl;

				return 0;
			}

			// CryptoTool.exe Provider -Name "ProviderName" -CreateKey -Name MyKey -Exportable <true|false> -IsMachineWide <true|false> -KeyLength 2048 -OverwriteIfExists <true|false>
			if(IsEqual(providerOperation, L"-CreateKey"))
			{
				if(!HasAtLeastNumArgs(14, totalArgs, command)) return -1;
				
				const auto isExportable = IsEqual(cmdArgs[8].c_str(), L"true");
				const auto isMachineWide = IsEqual(cmdArgs[10].c_str(), L"true");
				const auto overwriteExistingKey = IsEqual(cmdArgs[14].c_str(), L"true");
				const auto keyName = cmdArgs[6].c_str();
				auto dwFlags = (isMachineWide ? NCRYPT_MACHINE_KEY_FLAG : 0);
				if(overwriteExistingKey)
				{
					dwFlags |= NCRYPT_OVERWRITE_KEY_FLAG;
				}

				if(!IsNumber(cmdArgs[12]))
				{
					std::cout << "Invalid KeyLength: " << cmdArgs[12].c_str() << std::endl;
					PrintUsage(totalArgs, command);
					return -1; 
				}

				const auto keyLength = std::stoi(cmdArgs[12]);

				if(IsEqual(cmdArgs[5].c_str(), L"-Name") && 
				   IsEqual(cmdArgs[7].c_str(), L"-Exportable") &&
				   IsEqual(cmdArgs[9].c_str(), L"-IsMachineWide") &&
				   IsEqual(cmdArgs[11].c_str(), L"-KeyLength") &&
				   IsEqual(cmdArgs[13].c_str(), L"-OverwriteIfExists") &&
				    totalArgs == 14)
				{
					keyStorageProvider.CreateKey(keyName, isExportable, keyLength, dwFlags);
					return 0; // Finish command
				}

				// CryptoTool.exe Provider -Name "ProviderName" -CreateKey -Name MyKey -Exportable <true|false> -IsMachineWide <true|false> -KeyLength 2048 -OverwriteIfExists <true|false> [-Algorithm -Name <AlgorithmName>]
				if(!HasAtLeastNumArgs(17, totalArgs, command)) return -1;
					
				if(IsEqual(cmdArgs[15].c_str(), L"-Algorithm") && 
					IsEqual(cmdArgs[16].c_str(), L"-Name") && totalArgs == 17)
				{
					const auto algorithmName = cmdArgs[17].c_str();
					keyStorageProvider.CreateKey(keyName, isExportable, keyLength, dwFlags, algorithmName);
					return 0; // Finish command
				}				
			}

			// CryptoTool.exe Provider -Name "ProviderName" -DeleteKey -Name MyKey
			if(IsEqual(providerOperation, L"-DeleteKey"))
			{
				if(!HasAtLeastNumArgs(6, totalArgs, command)) return -1;

				const auto nameArg =  cmdArgs[5].c_str();
				const auto keyName = cmdArgs[6].c_str();
	
				if(IsEqual(nameArg, L"-Name"))
				{
					keyStorageProvider.DeleteKey(keyName);
					return 0; // Finish command
				}
			}
			
		}
	}
	else if (IsEqual(command, L"Key"))
	{
		if(!HasAtLeastNumArgs(6, totalArgs, command)) return -1;

		const auto operation = cmdArgs[6].c_str();
		const auto keyName = cmdArgs[3].c_str();
		const auto providerName = cmdArgs[5].c_str();

		Key key(keyName, providerName);
		key.Open();
		
		// CryptoTool.exe Key -Name "KeyName" -ProviderName "ProviderName" -GetProperty <NCRYPT_NAME_PROPERTY>
		if(IsEqual(operation, L"-GetProperty"))
		{
			if(!HasAtLeastNumArgs(7, totalArgs, command)) return -1;
			
			const auto propertyName = cmdArgs[7].c_str();

			
			std::wcout << key.GetProperty(propertyName, 0, 0, false) << std::endl;
			return 0;
		}
	}
	else if (IsEqual(command, L"CertificateAuthority"))
	{
		const auto templateName = L"User";
		const auto fileOut = L"Response.out";
		const auto signingTemplateName = L"User";  
		//EnrollFromPublicKey::Perform(templateName, fileOut, signingTemplateName);

		

		// CryptoTool.exe CertificateAuthority -GetDefault

		if(!HasAtLeastNumArgs(2, totalArgs, command)) return -1;

		const auto operation = cmdArgs[2].c_str();
		if(IsEqual(operation, L"-GetDefault"))
		{
			BSTR  bstrConfig = nullptr; //Contains CA configuration name
			if(CaConfig::GetCaConfig(&bstrConfig, CC_DEFAULTCONFIG) == S_OK)
			{
				const std::string strConfig(_bstr_t(bstrConfig, true));
				std::cout << strConfig << std::endl;
			    if (bstrConfig) 
				{
					SysFreeString(bstrConfig);
				}
			}
		}

		// CryptoTool.exe CertificateAuthority -Select
		if(IsEqual(operation, L"-Select"))
		{
			BSTR  bstrConfig = nullptr; //Contains CA configuration name
			if(CaConfig::GetCaConfig(&bstrConfig,CC_UIPICKCONFIG) == S_OK)
			{
				const std::string strConfig(_bstr_t(bstrConfig, true));
				std::cout << strConfig << std::endl;
			    if (bstrConfig) 
				{
					SysFreeString(bstrConfig);
				}
			}
		}

		return 0; // finished

	}

	// If not Finished, show help/usage
	PrintUsage(totalArgs, command);
}