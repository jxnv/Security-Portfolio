-- Title: Antivirus - Password Dumper Signature
-- ID: 78cc2dd2-7d20-4d32-93ff-057084c38b93
-- Status: stable
-- Level: critical
-- Author: Florian Roth (Nextron Systems), Arnim Rupp
-- Date: 2018-09-09
-- Tags: attack.credential-access, attack.t1003, attack.t1558, attack.t1003.001, attack.t1003.002
-- Description: Detects a highly relevant Antivirus alert that reports password dumpers and stealers.
-- This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place and check if passwords need to be reset.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Signature ILIKE 'PWS%') OR ((Signature ILIKE '%Certify%' OR Signature ILIKE '%DCSync%' OR Signature ILIKE '%Creddump%' OR Signature ILIKE '%DumpCreds%' OR Signature ILIKE '%DumpLsass%' OR Signature ILIKE '%DumpPert%' OR Signature ILIKE '%FormBook%' OR Signature ILIKE '%HTool/WCE%' OR Signature ILIKE '%Kekeo%' OR Signature ILIKE '%Lazagne%' OR Signature ILIKE '%LsassDump%' OR Signature ILIKE '%Lummast%' OR Signature ILIKE '%Mimikatz%' OR Signature ILIKE '%MultiDump%' OR Signature ILIKE '%Multiverze%' OR Signature ILIKE '%Nanodump%' OR Signature ILIKE '%NativeDump%' OR Signature ILIKE '%Outflank%' OR Signature ILIKE '%PShlSpy%' OR Signature ILIKE '%PSWTool%' OR Signature ILIKE '%PWCrack%' OR Signature ILIKE '%PWDump%' OR Signature ILIKE '%PWS.%' OR Signature ILIKE '%PWSX%' OR Signature ILIKE '%pypykatz%' OR Signature ILIKE '%Rubeus%' OR Signature ILIKE '%SafetyKatz%' OR Signature ILIKE '%SecurityTool%' OR Signature ILIKE '%SharpChrome%' OR Signature ILIKE '%SharpDPAPI%' OR Signature ILIKE '%SharpDump%' OR Signature ILIKE '%SharpKatz%' OR Signature ILIKE '%SharpS.%' OR Signature ILIKE '%ShpKatz%' OR Signature ILIKE '%Steal%' OR Signature ILIKE '%TrickDump%' OR Signature ILIKE '%wsass%')))
