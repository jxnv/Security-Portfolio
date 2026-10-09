-- Title: Uncommon Link.EXE Parent Process
-- ID: 6e968eb1-5f05-4dac-94e9-fd0c5cb49fd6
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-22
-- Tags: attack.stealth, attack.t1218
-- Description: Detects an uncommon parent process of "LINK.EXE".
-- Link.EXE in Microsoft incremental linker. Its a utility usually bundled with Visual Studio installation.
-- Multiple utilities often found in the same folder (editbin.exe, dumpbin.exe, lib.exe, etc) have a hardcode call to the "LINK.EXE" binary without checking its validity.
-- This would allow an attacker to sideload any binary with the name "link.exe" if one of the aforementioned tools get executed from a different location.
-- By filtering the known locations of such utilities we can spot uncommon parent process of LINK.EXE that might be suspicious or malicious.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\link.exe' AND CommandLine ILIKE '%LINK /%') AND NOT (((ParentImage ILIKE 'C:\\Program Files\\Microsoft Visual Studio\\%' OR ParentImage ILIKE 'C:\\Program Files (x86)\\Microsoft Visual Studio\\%') AND (ParentImage ILIKE '%\\VC\\bin\\%' OR ParentImage ILIKE '%\\VC\\Tools\\%'))))
