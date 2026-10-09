-- Title: Run Once Task Configuration in Registry
-- ID: c74d7efc-8826-45d9-b8bb-f04fac9e4eff
-- Status: test
-- Level: medium
-- Author: Avneet Singh @v3t0_, oscd.community
-- Date: 2020-11-15
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%\\Microsoft\\Active Setup\\Installed Components%' AND TargetObject ILIKE '%\\StubPath') AND NOT ((((Details ILIKE '%C:\\Program Files\\Google\\Chrome\\Application\\%' AND Details ILIKE '%\\Installer\\chrmstp.exe\" --configure-user-settings --verbose-logging --system-level%')) OR ((Details ILIKE '%C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\%' OR Details ILIKE '%C:\\Program Files\\Microsoft\\Edge\\Application\\%') AND Details ILIKE '%\\Installer\\setup.exe\" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable'))))
