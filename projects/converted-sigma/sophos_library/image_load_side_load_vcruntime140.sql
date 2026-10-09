-- Title: Potential Vcruntime140 DLL Sideloading
-- ID: d7a63acb-1284-49bc-bfea-7771146c8b1c
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-01-12
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of vcruntime140.dll, a common C++ runtime library.
-- Threat actors have been observed using DLL sideloading techniques to load malicious payloads under the guise of legitimate applications such as SqlWriter, SqlDumper etc.
-- Notably, APT29 has been documented leveraging WinELOADER to sideload vcruntime140.dll for executing malicious code.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ImageLoaded ILIKE '%\\vcruntime140.dll') AND NOT ((((ImageLoaded ILIKE 'C:\\Windows\\System32\\%' OR ImageLoaded ILIKE 'C:\\Windows\\SysWOW64\\%' OR ImageLoaded ILIKE 'C:\\Program Files\\%' OR ImageLoaded ILIKE 'C:\\Program Files (x86)\\%')) OR (Signed = True AND SignatureStatus = 'Valid' AND Description ILIKE '%C Runtime Library'))) AND NOT ((Image ILIKE 'C:\\Users\\%' AND Image ILIKE '%\\AppData\\Local\\Microsoft\\OneDrive\\%')))
