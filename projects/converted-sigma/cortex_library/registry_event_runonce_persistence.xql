// Title: Run Once Task Configuration in Registry
// ID: c74d7efc-8826-45d9-b8bb-f04fac9e4eff
// Status: test
// Level: medium
// Author: Avneet Singh @v3t0_, oscd.community
// Date: 2020-11-15
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Microsoft\\Active Setup\\Installed Components" and TargetObject endswith "\\StubPath") and not ((((Details contains "C:\\Program Files\\Google\\Chrome\\Application\\" and Details contains "\\Installer\\chrmstp.exe\" --configure-user-settings --verbose-logging --system-level")) or ((Details contains "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\" or Details contains "C:\\Program Files\\Microsoft\\Edge\\Application\\") and Details endswith "\\Installer\\setup.exe\" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable"))))
