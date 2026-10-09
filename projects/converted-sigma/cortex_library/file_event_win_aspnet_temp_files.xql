// Title: Assembly DLL Creation Via AspNetCompiler
// ID: 4c7f49ee-2638-43bb-b85b-ce676c30b260
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-14
// Tags: attack.execution
// Description: Detects the creation of new DLL assembly files by "aspnet_compiler.exe", which could be a sign of "aspnet_compiler" abuse to proxy execution through a build provider.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\aspnet_compiler.exe" and (action_file_path contains "\\Temporary ASP.NET Files\\" and action_file_path contains "\\assembly\\tmp\\" and action_file_path contains ".dll"))
