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

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\eqnedt32.exe' OR Image ILIKE '%\\wordpad.exe' OR Image ILIKE '%\\wordview.exe' OR Image ILIKE '%\\cmdl32.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\certoc.exe' OR Image ILIKE '%\\CertReq.exe' OR Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\Desktopimgdownldr.exe' OR Image ILIKE '%\\esentutl.exe' OR Image ILIKE '%\\expand.exe' OR Image ILIKE '%\\extrac32.exe' OR Image ILIKE '%\\replace.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\ftp.exe' OR Image ILIKE '%\\Ldifde.exe' OR Image ILIKE '%\\RdrCEF.exe' OR Image ILIKE '%\\hh.exe' OR Image ILIKE '%\\finger.exe' OR Image ILIKE '%\\findstr.exe')) AND ((TargetFilename ILIKE '%:\\Perflogs%' OR TargetFilename ILIKE '%:\\ProgramData\\%' OR TargetFilename ILIKE '%:\\Temp\\%' OR TargetFilename ILIKE '%:\\Users\\Public\\%' OR TargetFilename ILIKE '%:\\Windows\\%' OR TargetFilename ILIKE '%\\$Recycle.Bin\\%' OR TargetFilename ILIKE '%\\AppData\\Local\\%' OR TargetFilename ILIKE '%\\AppData\\Roaming\\%' OR TargetFilename ILIKE '%\\Contacts\\%' OR TargetFilename ILIKE '%\\Desktop\\%' OR TargetFilename ILIKE '%\\Favorites\\%' OR TargetFilename ILIKE '%\\Favourites\\%' OR TargetFilename ILIKE '%\\inetpub\\wwwroot\\%' OR TargetFilename ILIKE '%\\Music\\%' OR TargetFilename ILIKE '%\\Pictures\\%' OR TargetFilename ILIKE '%\\Start Menu\\Programs\\Startup\\%' OR TargetFilename ILIKE '%\\Users\\Default\\%' OR TargetFilename ILIKE '%\\Videos\\%')))
