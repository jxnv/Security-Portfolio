-- Title: Potentially Suspicious Mofcomp Execution
-- ID: 1dd05363-104e-4b4a-b963-196a534b03a1
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-12
-- Tags: attack.stealth, attack.t1218
-- Description: Detects execution of the "mofcomp" utility as a child of a suspicious shell or script running utility or by having a suspicious path in the commandline.
-- The "mofcomp" utility parses a file containing MOF statements and adds the classes and class instances defined in the file to the WMI repository.
-- Attackers abuse this utility to install malicious MOF scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((((ParentImage ILIKE '%\\cmd.exe' OR ParentImage ILIKE '%\\powershell.exe' OR ParentImage ILIKE '%\\pwsh.exe' OR ParentImage ILIKE '%\\wsl.exe' OR ParentImage ILIKE '%\\wscript.exe' OR ParentImage ILIKE '%\\cscript.exe')) OR ((CommandLine ILIKE '%\\AppData\\Local\\Temp%' OR CommandLine ILIKE '%\\Contacts\\%' OR CommandLine ILIKE '%\\Favorites\\%' OR CommandLine ILIKE '%\\Favourites\\%' OR CommandLine ILIKE '%\\Music\\%' OR CommandLine ILIKE '%\\Pictures\\%' OR CommandLine ILIKE '%\\Users\\Public\\%' OR CommandLine ILIKE '%\\Videos\\%' OR CommandLine ILIKE '%\\WINDOWS\\Temp\\%' OR CommandLine ILIKE '%%appdata%%' OR CommandLine ILIKE '%%temp%%' OR CommandLine ILIKE '%%tmp%%'))) AND ((Image ILIKE '%\\mofcomp.exe') OR (OriginalFileName = 'mofcomp.exe'))) AND NOT (((ParentCommandLine ILIKE '%\\InstallUtil.exe /Uninstall C:\\Windows\\CCM\\Microsoft.ConfigurationManager.SVProvider.dll' AND ParentImage ILIKE '%\\InstallUtil.exe' AND (CommandLine ILIKE '%C:\\Windows\\TEMP%' AND CommandLine ILIKE '%.tmp%')) OR (ParentImage = 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe' AND CommandLine ILIKE '%C:\\Windows\\TEMP\\%' AND CommandLine ILIKE '%.mof'))) AND NOT ((ParentCommandLine IS NULL)))
