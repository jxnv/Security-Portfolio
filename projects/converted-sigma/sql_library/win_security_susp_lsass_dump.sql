-- Title: Password Dumper Activity on LSASS
-- ID: aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c
-- Status: test
-- Level: high
-- Author: sigma
-- Date: 2017-02-12
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 4656 AND ProcessName ILIKE '%\\lsass.exe' AND AccessMask = '0x705' AND ObjectType = 'SAM_DOMAIN')
