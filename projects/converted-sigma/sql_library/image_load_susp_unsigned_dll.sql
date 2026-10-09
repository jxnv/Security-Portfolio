-- Title: Unsigned DLL Loaded by Windows Utility
-- ID: b5de0c9a-6f19-43e0-af4e-55ad01f550af
-- Status: test
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel
-- Date: 2024-02-28
-- Tags: attack.stealth, attack.t1218.011, attack.t1218.010
-- Description: Detects windows utilities loading an unsigned or untrusted DLL.
-- Adversaries often abuse those programs to proxy execution of malicious code.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\InstallUtil.exe' OR Image ILIKE '%\\RegAsm.exe' OR Image ILIKE '%\\RegSvcs.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe')) AND NOT ((((Image ILIKE 'C:\\Windows\\SysWOW64\\%' OR Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\Microsoft.NET\\Framework64%') AND Image ILIKE '%\\RegAsm.exe' AND ImageLoaded ILIKE '%.dll' AND ImageLoaded ILIKE 'C:\\Windows\\assembly\\NativeImages%') OR ((SignatureStatus = 'errorChaining' OR SignatureStatus = 'errorCode_endpoint' OR SignatureStatus = 'errorExpired' OR SignatureStatus = 'trusted' OR SignatureStatus = 'Valid')) OR ((SignatureStatus = '' OR SignatureStatus = '-')) OR (SignatureStatus IS NULL) OR (Signed = 'true') OR ((Signed = '' OR Signed = '-')) OR (Signed IS NULL) OR ((Image = 'C:\\Windows\\SysWOW64\\rundll32.exe' OR Image = 'C:\\Windows\\System32\\rundll32.exe') AND ImageLoaded ILIKE 'C:\\Windows\\Installer\\%' AND (ImageLoaded ILIKE '%.tmp-\\Microsoft.Deployment.WindowsInstaller.dll' OR ImageLoaded ILIKE '%.tmp-\\Avira.OE.Setup.CustomActions.dll')))) AND NOT (((Image = 'C:\\Windows\\SysWOW64\\regsvr32.exe' OR Image = 'C:\\Windows\\System32\\regsvr32.exe') AND (ImageLoaded ILIKE 'C:\\Program Files (x86)\\K-Lite Codec Pack\\%' OR ImageLoaded ILIKE 'C:\\Program Files\\K-Lite Codec Pack\\%'))))
