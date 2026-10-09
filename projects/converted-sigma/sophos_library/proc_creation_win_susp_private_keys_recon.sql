-- Title: Private Keys Reconnaissance Via CommandLine Tools
-- ID: 213d6a77-3d55-4ce8-ba74-fcfef741974e
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-07-20
-- Tags: attack.credential-access, attack.t1552.004
-- Description: Adversaries may search for private key certificate files on compromised systems for insecurely stored credential
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%.key%' OR CommandLine ILIKE '%.pgp%' OR CommandLine ILIKE '%.gpg%' OR CommandLine ILIKE '%.ppk%' OR CommandLine ILIKE '%.p12%' OR CommandLine ILIKE '%.pem%' OR CommandLine ILIKE '%.pfx%' OR CommandLine ILIKE '%.cer%' OR CommandLine ILIKE '%.p7b%' OR CommandLine ILIKE '%.asc%')) AND (((CommandLine ILIKE '%dir %') AND ((Image ILIKE '%\\cmd.exe') OR (OriginalFileName = 'Cmd.Exe'))) OR ((CommandLine ILIKE '%Get-ChildItem %') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')))) OR ((Image ILIKE '%\\findstr.exe') OR (OriginalFileName = 'FINDSTR.EXE'))))
