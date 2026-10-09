-- Title: HackTool - KrbRelay Execution
-- ID: e96253b8-6b3b-4f90-9e59-3b24b99cf9b4
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-04-27
-- Tags: attack.credential-access, attack.t1558.003
-- Description: Detects the use of KrbRelay, a Kerberos relaying tool
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% -spn %' AND CommandLine ILIKE '% -clsid %' AND CommandLine ILIKE '% -rbcd %')) OR ((CommandLine ILIKE '%shadowcred%' AND CommandLine ILIKE '%clsid%' AND CommandLine ILIKE '%spn%')) OR ((CommandLine ILIKE '%spn %' AND CommandLine ILIKE '%session %' AND CommandLine ILIKE '%clsid %')) OR ((Image ILIKE '%\\KrbRelay.exe') OR (OriginalFileName = 'KrbRelay.exe')))
