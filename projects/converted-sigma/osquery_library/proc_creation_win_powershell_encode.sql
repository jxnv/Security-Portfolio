-- Title: Suspicious Execution of Powershell with Base64
-- ID: fb843269-508c-4b76-8b8d-88679db22ce7
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-01-02
-- Tags: attack.execution, attack.t1059.001
-- Description: Commandline to launch powershell with a base64 payload
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '% -e %' OR CommandLine LIKE '% -en %' OR CommandLine LIKE '% -enc %' OR CommandLine LIKE '% -enco%' OR CommandLine LIKE '% -ec %')) AND NOT ((((ParentImage LIKE '%C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\%' OR ParentImage LIKE '%\\gc_worker.exe%')) OR (CommandLine LIKE '% -Encoding %'))))
