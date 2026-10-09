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

(((ScriptBlockText: "*Get-PasswordVaultCredentials*" OR ScriptBlockText: "*Get-CredManCreds*")) OR ((ScriptBlockText: "*New-Object*" AND ScriptBlockText: "*Windows.Security.Credentials.PasswordVault*")) OR ((ScriptBlockText: "*New-Object*" AND ScriptBlockText: "*Microsoft.CSharp.CSharpCodeProvider*" AND ScriptBlockText: "*[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())*" AND ScriptBlockText: "*Collections.ArrayList*" AND ScriptBlockText: "*System.CodeDom.Compiler.CompilerParameters*")))
