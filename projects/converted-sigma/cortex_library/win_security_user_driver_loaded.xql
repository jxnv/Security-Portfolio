// Title: Potential Privileged System Service Operation - SeLoadDriverPrivilege
// ID: f63508a0-c809-4435-b3be-ed819394d612
// Status: test
// Level: medium
// Author: xknow (@xknow_infosec), xorxes (@xor_xes)
// Date: 2019-04-08
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the usage of the 'SeLoadDriverPrivilege' privilege. This privilege is required to load or unload a device driver.
// With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode.
// This user right does not apply to Plug and Play device drivers.
// If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers.
// This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4673 and PrivilegeList = "SeLoadDriverPrivilege" and Service = "-") and not ((((ProcessName = "C:\\Windows\\explorer.exe" or ProcessName = "C:\\Windows\\HelpPane.exe" or ProcessName = "C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe" or ProcessName = "C:\\Windows\\System32\\Dism.exe" or ProcessName = "C:\\Windows\\System32\\fltMC.exe" or ProcessName = "C:\\Windows\\System32\\mmc.exe" or ProcessName = "C:\\Windows\\System32\\rundll32.exe" or ProcessName = "C:\\Windows\\System32\\RuntimeBroker.exe" or ProcessName = "C:\\Windows\\System32\\ShellHost.exe" or ProcessName = "C:\\Windows\\System32\\svchost.exe" or ProcessName = "C:\\Windows\\System32\\SystemSettingsBroker.exe" or ProcessName = "C:\\Windows\\System32\\wimserv.exe")) or (ProcessName startswith "C:\\Program Files\\WindowsApps\\Microsoft"))) and not ((((ProcessName startswith "C:\\Program Files (x86)\\Dropbox\\" or ProcessName startswith "C:\\Program Files\\Dropbox\\") and ProcessName endswith "\\Dropbox.exe") or ((ProcessName endswith "\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe" or ProcessName endswith "\\Google\\Chrome\\Application\\chrome.exe" or ProcessName endswith "\\procexp.exe" or ProcessName endswith "\\procexp64.exe" or ProcessName endswith "\\procexp64a.exe" or ProcessName endswith "\\procmon.exe" or ProcessName endswith "\\procmon64.exe" or ProcessName endswith "\\procmon64a.exe")))))
