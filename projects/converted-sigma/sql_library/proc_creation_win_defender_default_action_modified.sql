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

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%-LowThreatDefaultAction%' OR CommandLine ILIKE '%-ModerateThreatDefaultAction%' OR CommandLine ILIKE '%-HighThreatDefaultAction%' OR CommandLine ILIKE '%-SevereThreatDefaultAction%' OR CommandLine ILIKE '%-ltdefac %' OR CommandLine ILIKE '%-mtdefac %' OR CommandLine ILIKE '%-htdefac %' OR CommandLine ILIKE '%-stdefac %')) AND (CommandLine ILIKE '%Set-MpPreference%') AND ((CommandLine ILIKE '%Allow%' OR CommandLine ILIKE '%6%' OR CommandLine ILIKE '%NoAction%' OR CommandLine ILIKE '%9%')))
