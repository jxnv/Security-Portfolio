// Title: Dump Credentials from Windows Credential Manager With PowerShell
// ID: 99c49d9c-34ea-45f7-84a7-4751ae6b2cbc
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-20
// Tags: attack.credential-access, attack.t1555
// Description: Adversaries may search for common password storage locations to obtain user credentials.
// Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ScriptBlockText contains "Get-PasswordVaultCredentials" or ScriptBlockText contains "Get-CredManCreds")) or ((ScriptBlockText contains "New-Object" and ScriptBlockText contains "Windows.Security.Credentials.PasswordVault")) or ((ScriptBlockText contains "New-Object" and ScriptBlockText contains "Microsoft.CSharp.CSharpCodeProvider" and ScriptBlockText contains "[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())" and ScriptBlockText contains "Collections.ArrayList" and ScriptBlockText contains "System.CodeDom.Compiler.CompilerParameters")))
