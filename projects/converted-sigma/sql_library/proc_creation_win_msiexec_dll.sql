-- Title: DllUnregisterServer Function Call Via Msiexec.EXE
-- ID: 84f52741-8834-4a8c-a413-2eb2269aa6c8
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-04-24
-- Tags: attack.stealth, attack.t1218.007
-- Description: Detects MsiExec loading a DLL and calling its DllUnregisterServer function
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%.dll%') AND (CommandLine ILIKE '% -z %') AND ((Image ILIKE '%\\msiexec.exe') OR (OriginalFileName = '\\msiexec.exe')))
