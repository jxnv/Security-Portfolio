-- Title: UAC Notification Disabled
-- ID: c5f6a85d-b647-40f7-bbad-c10b66bab038
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-05-10
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects when an attacker tries to disable User Account Control (UAC) notification by tampering with the "UACDisableNotify" value.
-- UAC is a critical security feature in Windows that prevents unauthorized changes to the operating system. It prompts the user for permission or an administrator password before allowing actions that could affect the system's operation or change settings that affect other users.
-- When "UACDisableNotify" is set to 1, UAC prompts are suppressed.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (TargetObject LIKE '%\\Microsoft\\Security Center\\UACDisableNotify%' AND Details = 'DWORD (0x00000001)')
