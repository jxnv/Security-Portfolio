-- Title: Recon Command Output Piped To Findstr.EXE
-- ID: ccb5742c-c248-4982-8c5c-5571b9275ad3
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2023-07-06
-- Tags: attack.discovery, attack.t1057
-- Description: Detects the execution of a potential recon command where the results are piped to "findstr". This is meant to trigger on inline calls of "cmd.exe" via the "/c" or "/k" for example.
-- Attackers often time use this technique to extract specific information they require in their reconnaissance phase.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%ipconfig*|*find%' OR CommandLine LIKE '%net*|*find%' OR CommandLine LIKE '%netstat*|*find%' OR CommandLine LIKE '%ping*|*find%' OR CommandLine LIKE '%systeminfo*|*find%' OR CommandLine LIKE '%tasklist*|*find%' OR CommandLine LIKE '%whoami*|*find%')) AND NOT (((CommandLine LIKE '%cmd.exe /c TASKLIST /V |%' AND CommandLine LIKE '%FIND /I%' AND CommandLine LIKE '%\\xampp\\%' AND CommandLine LIKE '%\\catalina_start.bat%'))))
