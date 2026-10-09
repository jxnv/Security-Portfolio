-- Title: HKTL - SharpSuccessor Privilege Escalation Tool Execution
-- ID: 38a1ac5f-9c74-47d2-a345-dd6f5eb4e7c8
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-06-06
-- Tags: attack.privilege-escalation, attack.t1068
-- Description: Detects the execution of SharpSuccessor, a tool used to exploit the BadSuccessor attack for privilege escalation in WinServer 2025 Active Directory environments.
-- Successful usage of this tool can let the attackers gain the domain admin privileges by exploiting the BadSuccessor vulnerability.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\SharpSuccessor.exe') OR (OriginalFileName = 'SharpSuccessor.exe') OR (CommandLine ILIKE '%SharpSuccessor%') OR ((CommandLine ILIKE '% add %' AND CommandLine ILIKE '% /impersonate%' AND CommandLine ILIKE '% /path%' AND CommandLine ILIKE '% /account%' AND CommandLine ILIKE '% /name%')))
