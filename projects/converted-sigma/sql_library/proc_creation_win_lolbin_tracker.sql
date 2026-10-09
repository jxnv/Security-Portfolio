-- Title: Potential DLL Injection Or Execution Using Tracker.exe
-- ID: 148431ce-4b70-403d-8525-fcc2993f29ea
-- Status: test
-- Level: medium
-- Author: Avneet Singh @v3t0_, oscd.community
-- Date: 2020-10-18
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055.001
-- Description: Detects potential DLL injection and execution using "Tracker.exe"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '% /d %' OR CommandLine ILIKE '% /c %')) AND ((Image ILIKE '%\\tracker.exe') OR (Description = 'Tracker'))) AND NOT (((CommandLine ILIKE '% /ERRORREPORT:PROMPT %') OR ((ParentImage ILIKE '%\\Msbuild\\Current\\Bin\\MSBuild.exe' OR ParentImage ILIKE '%\\Msbuild\\Current\\Bin\\amd64\\MSBuild.exe')))))
