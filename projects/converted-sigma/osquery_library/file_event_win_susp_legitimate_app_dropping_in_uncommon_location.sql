-- Title: Legitimate Application Writing Files In Uncommon Location
-- ID: 1cf465a1-2609-4c15-9b66-c32dbe4bfd67
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-12-10
-- Tags: attack.stealth, attack.t1218, attack.command-and-control, attack.t1105
-- Description: Detects legitimate applications writing any type of file to uncommon or suspicious locations that are not typical for application data storage or execution.
-- Adversaries may leverage legitimate applications (Living off the Land Binaries - LOLBins) to drop or download malicious files to uncommon locations on the system to evade detection by security solutions.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((Image="*\\eqnedt32.exe" OR Image="*\\wordpad.exe" OR Image="*\\wordview.exe" OR Image="*\\cmdl32.exe" OR Image="*\\certutil.exe" OR Image="*\\certoc.exe" OR Image="*\\CertReq.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\Desktopimgdownldr.exe" OR Image="*\\esentutl.exe" OR Image="*\\expand.exe" OR Image="*\\extrac32.exe" OR Image="*\\replace.exe" OR Image="*\\mshta.exe" OR Image="*\\ftp.exe" OR Image="*\\Ldifde.exe" OR Image="*\\RdrCEF.exe" OR Image="*\\hh.exe" OR Image="*\\finger.exe" OR Image="*\\findstr.exe")) AND ((TargetFilename LIKE '%:\\Perflogs%' OR TargetFilename LIKE '%:\\ProgramData\\%' OR TargetFilename LIKE '%:\\Temp\\%' OR TargetFilename LIKE '%:\\Users\\Public\\%' OR TargetFilename LIKE '%:\\Windows\\%' OR TargetFilename LIKE '%\\$Recycle.Bin\\%' OR TargetFilename LIKE '%\\AppData\\Local\\%' OR TargetFilename LIKE '%\\AppData\\Roaming\\%' OR TargetFilename LIKE '%\\Contacts\\%' OR TargetFilename LIKE '%\\Desktop\\%' OR TargetFilename LIKE '%\\Favorites\\%' OR TargetFilename LIKE '%\\Favourites\\%' OR TargetFilename LIKE '%\\inetpub\\wwwroot\\%' OR TargetFilename LIKE '%\\Music\\%' OR TargetFilename LIKE '%\\Pictures\\%' OR TargetFilename LIKE '%\\Start Menu\\Programs\\Startup\\%' OR TargetFilename LIKE '%\\Users\\Default\\%' OR TargetFilename LIKE '%\\Videos\\%')))
