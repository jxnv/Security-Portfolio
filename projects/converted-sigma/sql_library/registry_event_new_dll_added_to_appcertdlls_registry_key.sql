-- Title: New DLL Added to AppCertDlls Registry Key
-- ID: 6aa1d992-5925-4e9f-a49b-845e51d1de01
-- Status: test
-- Level: medium
-- Author: Ilyas Ochkov, oscd.community
-- Date: 2019-10-25
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.009
-- Description: Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation
-- by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls') OR (NewName = 'HKLM\\SYSTEM\\CurentControlSet\\Control\\Session Manager\\AppCertDlls'))
