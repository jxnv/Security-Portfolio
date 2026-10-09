-- Title: Microsoft Office Protected View Disabled
-- ID: a5c7a43f-6009-4a8c-80c5-32abf1c53ecc
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-06-08
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects changes to Microsoft Office protected view registry keys with which the attacker disables this feature.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Office\\%' AND TargetObject ILIKE '%\\Security\\ProtectedView\\%')) AND ((Details = 'DWORD (0x00000000)' AND (TargetObject ILIKE '%\\enabledatabasefileprotectedview' OR TargetObject ILIKE '%\\enableforeigntextfileprotectedview')) OR (Details = 'DWORD (0x00000001)' AND (TargetObject ILIKE '%\\DisableAttachementsInPV' OR TargetObject ILIKE '%\\DisableInternetFilesInPV' OR TargetObject ILIKE '%\\DisableIntranetCheck' OR TargetObject ILIKE '%\\DisableUnsafeLocationsInPV'))))
