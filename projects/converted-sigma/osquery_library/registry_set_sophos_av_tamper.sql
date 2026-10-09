-- Title: Tamper With Sophos AV Registry Keys
-- ID: 9f4662ac-17ca-43aa-8f12-5d7b989d0101
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-02
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects tamper attempts to sophos av functionality via registry key modification
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\Sophos Endpoint Defense\\TamperProtection\\Config\\SAVEnabled%' OR TargetObject LIKE '%\\Sophos Endpoint Defense\\TamperProtection\\Config\\SEDEnabled%' OR TargetObject LIKE '%\\Sophos\\SAVService\\TamperProtection\\Enabled%') AND Details = 'DWORD (0x00000000)')
