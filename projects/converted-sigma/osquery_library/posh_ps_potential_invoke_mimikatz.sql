-- Title: Potential Invoke-Mimikatz PowerShell Script
-- ID: 189e3b02-82b2-4b90-9662-411eb64486d4
-- Status: test
-- Level: high
-- Author: Tim Rauch, Elastic (idea)
-- Date: 2022-09-28
-- Tags: attack.credential-access, attack.t1003
-- Description: Detects Invoke-Mimikatz PowerShell script and alike. Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '%DumpCreds%' AND ScriptBlockText LIKE '%DumpCerts%')) OR (ScriptBlockText LIKE '%sekurlsa::logonpasswords%') OR ((ScriptBlockText LIKE '%crypto::certificates%' AND ScriptBlockText LIKE '%CERT_SYSTEM_STORE_LOCAL_MACHINE%')))
