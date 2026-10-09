-- Title: Suspicious PowerShell Invocation From Script Engines
-- ID: 95eadcb2-92e4-4ed1-9031-92547773a6db
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-01-16
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious powershell invocations from interpreters or unusual programs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentImage ILIKE '%\\wscript.exe' OR ParentImage ILIKE '%\\cscript.exe') AND (Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) AND NOT ((CurrentDirectory ILIKE '%\\Health Service State\\%')))
