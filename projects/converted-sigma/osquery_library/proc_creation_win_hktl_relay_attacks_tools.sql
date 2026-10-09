-- Title: Potential SMB Relay Attack Tool Execution
-- ID: 5589ab4f-a767-433c-961d-c91f3f704db1
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-07-24
-- Tags: attack.collection, attack.execution, attack.credential-access, attack.t1557.001
-- Description: Detects different hacktools used for relay attacks on Windows for privilege escalation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.exe -c \"{%' AND CommandLine="*}\" -z") OR ((Image LIKE '%PetitPotam%' OR Image LIKE '%RottenPotato%' OR Image LIKE '%HotPotato%' OR Image LIKE '%JuicyPotato%' OR Image LIKE '%\\just_dce_%' OR Image LIKE '%Juicy Potato%' OR Image LIKE '%\\temp\\rot.exe%' OR Image LIKE '%\\Potato.exe%' OR Image LIKE '%\\SpoolSample.exe%' OR Image LIKE '%\\Responder.exe%' OR Image LIKE '%\\smbrelayx%' OR Image LIKE '%\\ntlmrelayx%' OR Image LIKE '%\\LocalPotato%')) OR ((CommandLine LIKE '%Invoke-Tater%' OR CommandLine LIKE '% smbrelay%' OR CommandLine LIKE '% ntlmrelay%' OR CommandLine LIKE '%cme smb %' OR CommandLine LIKE '% /ntlm:NTLMhash %' OR CommandLine LIKE '%Invoke-PetitPotam%' OR CommandLine LIKE '%.exe -t * -p %'))) AND NOT (((Image LIKE '%HotPotatoes6%' OR Image LIKE '%HotPotatoes7%' OR Image LIKE '%HotPotatoes %'))))
