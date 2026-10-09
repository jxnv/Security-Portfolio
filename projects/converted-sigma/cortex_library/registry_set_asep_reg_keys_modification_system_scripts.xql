// Title: System Scripts Autorun Keys Modification
// ID: e7a2fd40-3ae1-4a85-bf80-15cf624fb1b1
// Status: test
// Level: medium
// Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
// Date: 2019-10-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects modification of autostart extensibility point (ASEP) in registry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts") and ((TargetObject contains "\\Startup" or TargetObject contains "\\Shutdown" or TargetObject contains "\\Logon" or TargetObject contains "\\Logoff")) and not ((Details = "(Empty)")))
