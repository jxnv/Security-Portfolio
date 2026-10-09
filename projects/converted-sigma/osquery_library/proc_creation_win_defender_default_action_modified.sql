-- Title: PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction'
-- ID: 1e8a9b4d-3c2a-4f9b-8d1e-7c6a5b4f3d2e
-- Status: experimental
-- Level: high
-- Author: Matt Anderson (Huntress)
-- Date: 2025-07-11
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the use of PowerShell to execute the 'Set-MpPreference' cmdlet to configure Windows Defender's threat severity default action to 'Allow' (value '6') or 'NoAction' (value '9').
-- This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level.
-- An attacker might use this technique via the command line to bypass defenses before executing payloads.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%-LowThreatDefaultAction%' OR CommandLine LIKE '%-ModerateThreatDefaultAction%' OR CommandLine LIKE '%-HighThreatDefaultAction%' OR CommandLine LIKE '%-SevereThreatDefaultAction%' OR CommandLine LIKE '%-ltdefac %' OR CommandLine LIKE '%-mtdefac %' OR CommandLine LIKE '%-htdefac %' OR CommandLine LIKE '%-stdefac %')) AND (CommandLine LIKE '%Set-MpPreference%') AND ((CommandLine LIKE '%Allow%' OR CommandLine LIKE '%6%' OR CommandLine LIKE '%NoAction%' OR CommandLine LIKE '%9%')))
