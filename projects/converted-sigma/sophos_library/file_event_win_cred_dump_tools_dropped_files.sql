-- Title: Cred Dump Tools Dropped Files
-- ID: 8fbf3271-1ef6-4e94-8210-03c2317947f6
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, oscd.community
-- Date: 2019-11-01
-- Tags: attack.credential-access, attack.t1003.001, attack.t1003.002, attack.t1003.003, attack.t1003.004, attack.t1003.005
-- Description: Files with well-known filenames (parts of credential dump software or files produced by them) creation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetFilename ILIKE '%\\fgdump-log%' OR TargetFilename ILIKE '%\\kirbi%' OR TargetFilename ILIKE '%\\pwdump%' OR TargetFilename ILIKE '%\\pwhashes%' OR TargetFilename ILIKE '%\\wce_ccache%' OR TargetFilename ILIKE '%\\wce_krbtkts%')) OR ((TargetFilename ILIKE '%\\cachedump.exe' OR TargetFilename ILIKE '%\\cachedump64.exe' OR TargetFilename ILIKE '%\\DumpExt.dll' OR TargetFilename ILIKE '%\\DumpSvc.exe' OR TargetFilename ILIKE '%\\Dumpy.exe' OR TargetFilename ILIKE '%\\fgexec.exe' OR TargetFilename ILIKE '%\\lsremora.dll' OR TargetFilename ILIKE '%\\lsremora64.dll' OR TargetFilename ILIKE '%\\NTDS.out' OR TargetFilename ILIKE '%\\procdump.exe' OR TargetFilename ILIKE '%\\procdump64.exe' OR TargetFilename ILIKE '%\\procdump64a.exe' OR TargetFilename ILIKE '%\\pstgdump.exe' OR TargetFilename ILIKE '%\\pwdump.exe' OR TargetFilename ILIKE '%\\SAM.out' OR TargetFilename ILIKE '%\\SECURITY.out' OR TargetFilename ILIKE '%\\servpw.exe' OR TargetFilename ILIKE '%\\servpw64.exe' OR TargetFilename ILIKE '%\\SYSTEM.out' OR TargetFilename ILIKE '%\\test.pwd' OR TargetFilename ILIKE '%\\wceaux.dll')))
