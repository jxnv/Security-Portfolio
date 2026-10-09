-- Title: Dump Credentials from Windows Credential Manager With PowerShell
-- ID: 99c49d9c-34ea-45f7-84a7-4751ae6b2cbc
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-20
-- Tags: attack.credential-access, attack.t1555
-- Description: Adversaries may search for common password storage locations to obtain user credentials.
-- Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ScriptBlockText ILIKE '%Get-PasswordVaultCredentials%' OR ScriptBlockText ILIKE '%Get-CredManCreds%')) OR ((ScriptBlockText ILIKE '%New-Object%' AND ScriptBlockText ILIKE '%Windows.Security.Credentials.PasswordVault%')) OR ((ScriptBlockText ILIKE '%New-Object%' AND ScriptBlockText ILIKE '%Microsoft.CSharp.CSharpCodeProvider%' AND ScriptBlockText ILIKE '%[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())%' AND ScriptBlockText ILIKE '%Collections.ArrayList%' AND ScriptBlockText ILIKE '%System.CodeDom.Compiler.CompilerParameters%')))
