-- Title: HackTool - CrackMapExec Execution
-- ID: 42a993dd-bb3e-48c8-b372-4d6684c4106c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-25
-- Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.credential-access, attack.discovery, attack.t1047, attack.t1053, attack.t1059.003, attack.t1059.001, attack.t1110, attack.t1201
-- Description: This rule detect common flag combinations used by CrackMapExec in order to detect its use even if the binary has been replaced.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\crackmapexec.exe') OR ((CommandLine ILIKE '% --local-auth%' AND CommandLine ILIKE '% -u %' AND CommandLine ILIKE '% -x %')) OR ((CommandLine ILIKE '% --local-auth%' AND CommandLine ILIKE '% -u %' AND CommandLine ILIKE '% -p %' AND CommandLine ILIKE '% -H 'NTHASH'%')) OR ((CommandLine ILIKE '% mssql %' AND CommandLine ILIKE '% -u %' AND CommandLine ILIKE '% -p %' AND CommandLine ILIKE '% -M %' AND CommandLine ILIKE '% -d %')) OR ((CommandLine ILIKE '% smb %' AND CommandLine ILIKE '% -u %' AND CommandLine ILIKE '% -H %' AND CommandLine ILIKE '% -M %' AND CommandLine ILIKE '% -o %')) OR ((CommandLine ILIKE '% smb %' AND CommandLine ILIKE '% -u %' AND CommandLine ILIKE '% -p %' AND CommandLine ILIKE '% --local-auth%')) OR (CommandLine ILIKE '% -M pe_inject %')) OR (((CommandLine ILIKE '% --local-auth%' AND CommandLine ILIKE '% -u %' AND CommandLine ILIKE '% -p %')) AND ((CommandLine ILIKE '% 10.%' AND CommandLine ILIKE '% 192.168.%' AND CommandLine ILIKE '%/24 %'))))
