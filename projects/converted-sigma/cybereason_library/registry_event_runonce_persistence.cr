// Title: Run Once Task Configuration in Registry
// ID: c74d7efc-8826-45d9-b8bb-f04fac9e4eff
// Status: test
// Level: medium
// Author: Avneet Singh @v3t0_, oscd.community
// Date: 2020-11-15
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject contains "\\Microsoft\\Active Setup\\Installed Components" AND TargetObject="*\\StubPath") AND NOT ((((Details contains "C:\\Program Files\\Google\\Chrome\\Application\\" AND Details contains "\\Installer\\chrmstp.exe\" --configure-user-settings --verbose-logging --system-level")) OR ((Details contains "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\" OR Details contains "C:\\Program Files\\Microsoft\\Edge\\Application\\") AND Details="*\\Installer\\setup.exe\" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable"))))
