-- Title: RestrictedAdminMode Registry Value Tampering
-- ID: d6ce7ebd-260b-4323-9768-a9631c8d4db2
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2023-01-13
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects changes to the "DisableRestrictedAdmin" registry value in order to disable or enable RestrictedAdmin mode.
-- RestrictedAdmin mode prevents the transmission of reusable credentials to the remote system to which you connect using Remote Desktop.
-- This prevents your credentials from being harvested during the initial connection process if the remote server has been compromise
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetObject ILIKE '%System\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin')
