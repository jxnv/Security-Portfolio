-- Title: Private Keys Reconnaissance Via CommandLine Tools
-- ID: 213d6a77-3d55-4ce8-ba74-fcfef741974e
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-07-20
-- Tags: attack.credential-access, attack.t1552.004
-- Description: Adversaries may search for private key certificate files on compromised systems for insecurely stored credential
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.key%' OR CommandLine LIKE '%.pgp%' OR CommandLine LIKE '%.gpg%' OR CommandLine LIKE '%.ppk%' OR CommandLine LIKE '%.p12%' OR CommandLine LIKE '%.pem%' OR CommandLine LIKE '%.pfx%' OR CommandLine LIKE '%.cer%' OR CommandLine LIKE '%.p7b%' OR CommandLine LIKE '%.asc%')) AND (((CommandLine LIKE '%dir %') AND ((Image="*\\cmd.exe") OR (OriginalFileName = 'Cmd.Exe'))) OR ((CommandLine LIKE '%Get-ChildItem %') AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')))) OR ((Image="*\\findstr.exe") OR (OriginalFileName = 'FINDSTR.EXE'))))
