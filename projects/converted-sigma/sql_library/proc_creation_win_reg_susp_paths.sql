-- Title: Reg Add Suspicious Paths
-- ID: b7e2a8d4-74bb-4b78-adc9-3f92af2d4829
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-19
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112, attack.t1685
-- Description: Detects when an adversary uses the reg.exe utility to add or modify new keys or subkeys
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%\\AppDataLow\\Software\\Microsoft\\%' OR CommandLine ILIKE '%\\Policies\\Microsoft\\Windows\\OOBE%' OR CommandLine ILIKE '%\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon%' OR CommandLine ILIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon%' OR CommandLine ILIKE '%\\CurrentControlSet\\Control\\SecurityProviders\\WDigest%' OR CommandLine ILIKE '%\\Microsoft\\Windows Defender\\%')) AND ((Image ILIKE '%\\reg.exe') OR (OriginalFileName = 'reg.exe')))
