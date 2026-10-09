-- Title: HackTool - Impersonate Execution
-- ID: cf0c254b-22f1-4b2b-8221-e137b3c0af94
-- Status: test
-- Level: medium
-- Author: Sai Prashanth Pulisetti @pulisettis
-- Date: 2022-12-21
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.003
-- Description: Detects execution of the Impersonate tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%impersonate.exe%') AND ((CommandLine ILIKE '% list %' OR CommandLine ILIKE '% exec %' OR CommandLine ILIKE '% adduser %'))) OR ((Hashes ILIKE '%MD5=9520714AB576B0ED01D1513691377D01%' OR Hashes ILIKE '%SHA256=E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A%' OR Hashes ILIKE '%IMPHASH=0A358FFC1697B7A07D0E817AC740DF62%')))
