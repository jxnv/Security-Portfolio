// Title: Session Manager Autorun Keys Modification
// ID: 046218bd-e0d8-4113-a3c3-895a12b2b298
// Status: test
// Level: medium
// Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
// Date: 2019-10-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001, attack.t1546.009
// Description: Detects modification of autostart extensibility point (ASEP) in registry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\System\\CurrentControlSet\\Control\\Session Manager") and ((TargetObject contains "\\SetupExecute" or TargetObject contains "\\S0InitialCommand" or TargetObject contains "\\KnownDlls" or TargetObject contains "\\Execute" or TargetObject contains "\\BootExecute" or TargetObject contains "\\AppCertDlls")) and not ((Details = "(Empty)")))
