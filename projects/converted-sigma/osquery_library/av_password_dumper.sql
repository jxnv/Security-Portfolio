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

SELECT * FROM file WHERE ((Signature="PWS*") OR ((Signature LIKE '%Certify%' OR Signature LIKE '%DCSync%' OR Signature LIKE '%Creddump%' OR Signature LIKE '%DumpCreds%' OR Signature LIKE '%DumpLsass%' OR Signature LIKE '%DumpPert%' OR Signature LIKE '%FormBook%' OR Signature LIKE '%HTool/WCE%' OR Signature LIKE '%Kekeo%' OR Signature LIKE '%Lazagne%' OR Signature LIKE '%LsassDump%' OR Signature LIKE '%Lummast%' OR Signature LIKE '%Mimikatz%' OR Signature LIKE '%MultiDump%' OR Signature LIKE '%Multiverze%' OR Signature LIKE '%Nanodump%' OR Signature LIKE '%NativeDump%' OR Signature LIKE '%Outflank%' OR Signature LIKE '%PShlSpy%' OR Signature LIKE '%PSWTool%' OR Signature LIKE '%PWCrack%' OR Signature LIKE '%PWDump%' OR Signature LIKE '%PWS.%' OR Signature LIKE '%PWSX%' OR Signature LIKE '%pypykatz%' OR Signature LIKE '%Rubeus%' OR Signature LIKE '%SafetyKatz%' OR Signature LIKE '%SecurityTool%' OR Signature LIKE '%SharpChrome%' OR Signature LIKE '%SharpDPAPI%' OR Signature LIKE '%SharpDump%' OR Signature LIKE '%SharpKatz%' OR Signature LIKE '%SharpS.%' OR Signature LIKE '%ShpKatz%' OR Signature LIKE '%Steal%' OR Signature LIKE '%TrickDump%' OR Signature LIKE '%wsass%')))
