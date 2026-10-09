-- Title: Registry Enumeration via WMI Stdregprov
-- ID: a0e417e2-2fa1-40da-b6d2-e094cd5e1191
-- Status: experimental
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-07-30
-- Tags: attack.execution, attack.t1047, attack.discovery, attack.t1012
-- Description: Detects the usage of wmic.exe to enumerate or read Windows registry via the WMI StdRegProv class read methods (EnumKey, EnumValues, GetStringValue, etc.).
-- While registry reads are common, attackers may use this technique to perform reconnaissance and discover sensitive configuration values, credentials, or installed software.
-- The use of WMI as an alternative to standard tools like reg.exe can indicate an attempt to evade detection focused on traditional registry query commands.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%stdregprov%' AND CommandLine LIKE '%call%') AND (CommandLine LIKE '%CheckAccess%' OR CommandLine LIKE '%EnumKey%' OR CommandLine LIKE '%EnumValues%' OR CommandLine LIKE '%GetBinaryValue%' OR CommandLine LIKE '%GetDWORDValue%' OR CommandLine LIKE '%GetExpandedStringValue%' OR CommandLine LIKE '%GetMultiStringValue%' OR CommandLine LIKE '%GetQWORDValue%' OR CommandLine LIKE '%GetSecurityDescriptor%' OR CommandLine LIKE '%GetStringValue%')) AND ((Image="*\\wmic.exe") OR (OriginalFileName = 'wmic.exe')))
