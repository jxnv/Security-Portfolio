-- Title: Disable PUA Protection on Windows Defender
-- ID: 8ffc5407-52e3-478f-9596-0a7371eafe13
-- Status: test
-- Level: high
-- Author: Austin Songer @austinsonger
-- Date: 2021-08-04
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects disabling Windows Defender PUA protection
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (TargetObject LIKE '%\\Policies\\Microsoft\\Windows Defender\\PUAProtection%' AND Details = 'DWORD (0x00000000)')
