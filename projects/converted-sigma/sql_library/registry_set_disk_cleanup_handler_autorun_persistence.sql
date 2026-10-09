-- Title: Persistence Via Disk Cleanup Handler - Autorun
-- ID: d4e2745c-f0c6-4bde-a3ab-b553b3f693cc
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-21
-- Tags: attack.persistence
-- Description: Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence via autorun.
-- The disk cleanup manager is part of the operating system.
-- It displays the dialog box […] The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI.
-- Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications.
-- Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler.
-- Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\%') AND ((TargetObject ILIKE '%\\Autorun%' AND Details = 'DWORD (0x00000001)') OR ((TargetObject ILIKE '%\\CleanupString%' OR TargetObject ILIKE '%\\PreCleanupString%') AND (Details ILIKE '%cmd%' OR Details ILIKE '%powershell%' OR Details ILIKE '%rundll32%' OR Details ILIKE '%mshta%' OR Details ILIKE '%cscript%' OR Details ILIKE '%wscript%' OR Details ILIKE '%wsl%' OR Details ILIKE '%\\Users\\Public\\%' OR Details ILIKE '%\\Windows\\TEMP\\%' OR Details ILIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%'))))
