-- Title: HackTool - CrackMapExec Execution
-- ID: 42a993dd-bb3e-48c8-b372-4d6684c4106c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-25
-- Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.credential-access, attack.discovery, attack.t1047, attack.t1053, attack.t1059.003, attack.t1059.001, attack.t1110, attack.t1201
-- Description: This rule detect common flag combinations used by CrackMapExec in order to detect its use even if the binary has been replaced.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\crackmapexec.exe") OR ((CommandLine LIKE '% --local-auth%' AND CommandLine LIKE '% -u %' AND CommandLine LIKE '% -x %')) OR ((CommandLine LIKE '% --local-auth%' AND CommandLine LIKE '% -u %' AND CommandLine LIKE '% -p %' AND CommandLine LIKE '% -H 'NTHASH'%')) OR ((CommandLine LIKE '% mssql %' AND CommandLine LIKE '% -u %' AND CommandLine LIKE '% -p %' AND CommandLine LIKE '% -M %' AND CommandLine LIKE '% -d %')) OR ((CommandLine LIKE '% smb %' AND CommandLine LIKE '% -u %' AND CommandLine LIKE '% -H %' AND CommandLine LIKE '% -M %' AND CommandLine LIKE '% -o %')) OR ((CommandLine LIKE '% smb %' AND CommandLine LIKE '% -u %' AND CommandLine LIKE '% -p %' AND CommandLine LIKE '% --local-auth%')) OR (CommandLine LIKE '% -M pe_inject %')) OR (((CommandLine LIKE '% --local-auth%' AND CommandLine LIKE '% -u %' AND CommandLine LIKE '% -p %')) AND ((CommandLine LIKE '% 10.%' AND CommandLine LIKE '% 192.168.%' AND CommandLine LIKE '%/24 %'))))
