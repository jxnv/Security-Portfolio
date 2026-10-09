-- Title: Obfuscated PowerShell OneLiner Execution
-- ID: 44e24481-6202-4c62-9127-5a0ae8e3fe3d
-- Status: test
-- Level: high
-- Author: @Kostastsale, TheDFIRReport
-- Date: 2022-05-09
-- Tags: attack.execution, attack.defense-impairment, attack.t1059.001, attack.t1685
-- Description: Detects the execution of a specific OneLiner to download and execute powershell modules in memory.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*\\powershell.exe" AND (CommandLine LIKE '%http://127.0.0.1%' AND CommandLine LIKE '%%{(IRM $_)}%' AND CommandLine LIKE '%Invoke%'))
