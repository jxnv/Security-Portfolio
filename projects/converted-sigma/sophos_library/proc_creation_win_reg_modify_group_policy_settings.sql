-- Title: Modify Group Policy Settings
-- ID: ada4b0c4-758b-46ac-9033-9004613a150d
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-08-19
-- Tags: attack.privilege-escalation, attack.defense-impairment, attack.t1484.001
-- Description: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%GroupPolicyRefreshTimeDC%' OR CommandLine ILIKE '%GroupPolicyRefreshTimeOffsetDC%' OR CommandLine ILIKE '%GroupPolicyRefreshTime%' OR CommandLine ILIKE '%GroupPolicyRefreshTimeOffset%' OR CommandLine ILIKE '%EnableSmartScreen%' OR CommandLine ILIKE '%ShellSmartScreenLevel%')) AND (CommandLine ILIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows\\System%') AND ((Image ILIKE '%\\reg.exe') OR (OriginalFileName = 'reg.exe')))
