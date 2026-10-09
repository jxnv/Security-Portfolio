-- Title: Registry Manipulation via WMI Stdregprov
-- ID: c453ab7a-1f5c-4716-a3b4-dea8135fb43a
-- Status: experimental
-- Level: medium
-- Author: Daniel Koifman (KoifSec)
-- Date: 2025-07-30
-- Tags: attack.execution, attack.t1047, attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects the usage of wmic.exe to modify Windows registry via the WMI StdRegProv class write methods (CreateKey, DeleteKey, SetStringValue, etc.).
-- This behaviour could be potentially suspicious because it uses an alternative method to modify registry keys instead of legitimate registry tools like reg.exe or regedit.exe.
-- Attackers specifically choose this technique to evade detection and bypass security monitoring focused on traditional registry modification commands.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%stdregprov%' AND CommandLine ILIKE '%call%') AND (CommandLine ILIKE '%CreateKey%' OR CommandLine ILIKE '%DeleteKey%' OR CommandLine ILIKE '%DeleteValue%' OR CommandLine ILIKE '%SetBinaryValue%' OR CommandLine ILIKE '%SetDWORDValue%' OR CommandLine ILIKE '%SetExpandedStringValue%' OR CommandLine ILIKE '%SetMultiStringValue%' OR CommandLine ILIKE '%SetQWORDValue%' OR CommandLine ILIKE '%SetSecurityDescriptor%' OR CommandLine ILIKE '%SetStringValue%')) AND ((Image ILIKE '%\\wmic.exe') OR (OriginalFileName = 'wmic.exe')))
