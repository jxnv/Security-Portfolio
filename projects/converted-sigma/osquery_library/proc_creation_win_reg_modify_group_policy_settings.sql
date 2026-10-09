-- Title: Modify Group Policy Settings
-- ID: ada4b0c4-758b-46ac-9033-9004613a150d
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-08-19
-- Tags: attack.privilege-escalation, attack.defense-impairment, attack.t1484.001
-- Description: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%GroupPolicyRefreshTimeDC%' OR CommandLine LIKE '%GroupPolicyRefreshTimeOffsetDC%' OR CommandLine LIKE '%GroupPolicyRefreshTime%' OR CommandLine LIKE '%GroupPolicyRefreshTimeOffset%' OR CommandLine LIKE '%EnableSmartScreen%' OR CommandLine LIKE '%ShellSmartScreenLevel%')) AND (CommandLine LIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows\\System%') AND ((Image="*\\reg.exe") OR (OriginalFileName = 'reg.exe')))
