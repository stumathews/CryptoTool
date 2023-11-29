# CryptoTool
Simple Diagnostic tool to query Cryptographic providers and create RSA keys.
Allows you to list the registered cryptographic providers in windows and create RSA keys with them.

## Usage

### Key 
CryptoTool.exe Key -Name <KeyName> -ProviderName <ProviderName> -GetProperty <NCRYPT_NAME_PROPERTY>

### Certificate Authority
CryptoTool.exe CertificateAuthority -GetDefault
CryptoTool.exe CertificateAuthority -Select
CryptoTool.exe CertificateAuthority -GetField <FieldName> eg fields: CommonName|Config|Flags|Server etc.

### Crypto Provider[s]
CryptTool.exe Providers [-List]
CryptTool.exe Provider -Name <ProviderName> -ListKeys
CryptoTool.exe Provider -Name <ProviderName> -CreateKey -Name MyKey -Exportable <true|false> -IsMachineWide <true|false> -KeyLength 2048 -OverwriteIfExists <true|false> [-Algorithm -Name <AlgorithmName>]
CryptTool.exe Provider -Name <ProviderName> -DeleteKey -Name <KeyName>
CryptoTool.exe Provider -Name <ProviderName> -GetProperty <NCRYPT_NAME_PROPERTY>
