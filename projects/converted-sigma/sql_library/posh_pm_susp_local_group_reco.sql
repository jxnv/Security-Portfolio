-- Title: Suspicious Get Local Groups Information
-- ID: cef24b90-dddc-4ae1-a09a-8764872f69fc
-- Status: test
-- Level: low
-- Author: frack113
-- Date: 2021-12-12
-- Tags: attack.discovery, attack.t1069.001
-- Description: Detects the use of PowerShell modules and cmdlets to gather local group information.
-- Adversaries may use local system permission groups to determine which groups exist and which users belong to a particular group such as the local administrators group.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Payload ILIKE '%get-localgroup %' OR Payload ILIKE '%get-localgroupmember %')) OR ((ContextInfo ILIKE '%get-localgroup %' OR ContextInfo ILIKE '%get-localgroupmember %'))) OR (((Payload ILIKE '%win32_group%') OR (ContextInfo ILIKE '%win32_group%')) AND (((Payload ILIKE '%get-wmiobject %' OR Payload ILIKE '%gwmi %' OR Payload ILIKE '%get-ciminstance %' OR Payload ILIKE '%gcim %')) OR ((ContextInfo ILIKE '%get-wmiobject %' AND ContextInfo ILIKE '%gwmi %' AND ContextInfo ILIKE '%get-ciminstance %' AND ContextInfo ILIKE '%gcim %')))))
