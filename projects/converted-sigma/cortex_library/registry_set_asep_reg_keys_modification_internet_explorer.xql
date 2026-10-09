// Title: Internet Explorer Autorun Keys Modification
// ID: a80f662f-022f-4429-9b8c-b1a41aaa6688
// Status: test
// Level: medium
// Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
// Date: 2019-10-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects modification of autostart extensibility point (ASEP) in registry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\Software\\Wow6432Node\\Microsoft\\Internet Explorer" or TargetObject contains "\\Software\\Microsoft\\Internet Explorer")) and ((TargetObject contains "\\Toolbar" or TargetObject contains "\\Extensions" or TargetObject contains "\\Explorer Bars")) and not (((Details = "(Empty)") or ((TargetObject contains "\\Extensions\\{2670000A-7350-4f3c-8081-5663EE0C6C49}" or TargetObject contains "\\Extensions\\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" or TargetObject contains "\\Extensions\\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" or TargetObject contains "\\Extensions\\{A95fe080-8f5d-11d2-a20b-00aa003c157a}")) or ((TargetObject endswith "\\Toolbar\\ShellBrowser\\ITBar7Layout" or TargetObject endswith "\\Toolbar\\ShowDiscussionButton" or TargetObject endswith "\\Toolbar\\Locked")))))
