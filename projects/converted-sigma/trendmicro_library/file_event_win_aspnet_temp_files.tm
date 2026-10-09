// Title: Assembly DLL Creation Via AspNetCompiler
// ID: 4c7f49ee-2638-43bb-b85b-ce676c30b260
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-14
// Tags: attack.execution
// Description: Detects the creation of new DLL assembly files by "aspnet_compiler.exe", which could be a sign of "aspnet_compiler" abuse to proxy execution through a build provider.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*\\aspnet_compiler.exe" AND (TargetFilename: "*\\Temporary ASP.NET Files\\*" AND TargetFilename: "*\\assembly\\tmp\\*" AND TargetFilename: "*.dll*"))
