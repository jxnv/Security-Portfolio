-- Title: Potential Privileged System Service Operation - SeLoadDriverPrivilege
-- ID: f63508a0-c809-4435-b3be-ed819394d612
-- Status: test
-- Level: medium
-- Author: xknow (@xknow_infosec), xorxes (@xor_xes)
-- Date: 2019-04-08
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the usage of the 'SeLoadDriverPrivilege' privilege. This privilege is required to load or unload a device driver.
-- With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode.
-- This user right does not apply to Plug and Play device drivers.
-- If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers.
-- This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((EventID = 4673 AND PrivilegeList = 'SeLoadDriverPrivilege' AND Service = '-') AND NOT ((((ProcessName = 'C:\\Windows\\explorer.exe' OR ProcessName = 'C:\\Windows\\HelpPane.exe' OR ProcessName = 'C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe' OR ProcessName = 'C:\\Windows\\System32\\Dism.exe' OR ProcessName = 'C:\\Windows\\System32\\fltMC.exe' OR ProcessName = 'C:\\Windows\\System32\\mmc.exe' OR ProcessName = 'C:\\Windows\\System32\\rundll32.exe' OR ProcessName = 'C:\\Windows\\System32\\RuntimeBroker.exe' OR ProcessName = 'C:\\Windows\\System32\\ShellHost.exe' OR ProcessName = 'C:\\Windows\\System32\\svchost.exe' OR ProcessName = 'C:\\Windows\\System32\\SystemSettingsBroker.exe' OR ProcessName = 'C:\\Windows\\System32\\wimserv.exe')) OR (ProcessName ILIKE 'C:\\Program Files\\WindowsApps\\Microsoft%'))) AND NOT ((((ProcessName ILIKE 'C:\\Program Files (x86)\\Dropbox\\%' OR ProcessName ILIKE 'C:\\Program Files\\Dropbox\\%') AND ProcessName ILIKE '%\\Dropbox.exe') OR ((ProcessName ILIKE '%\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe' OR ProcessName ILIKE '%\\Google\\Chrome\\Application\\chrome.exe' OR ProcessName ILIKE '%\\procexp.exe' OR ProcessName ILIKE '%\\procexp64.exe' OR ProcessName ILIKE '%\\procexp64a.exe' OR ProcessName ILIKE '%\\procmon.exe' OR ProcessName ILIKE '%\\procmon64.exe' OR ProcessName ILIKE '%\\procmon64a.exe')))))
