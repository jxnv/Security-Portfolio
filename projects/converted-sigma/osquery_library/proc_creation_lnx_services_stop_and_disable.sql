-- Title: Disable Or Stop Services
-- ID: de25eeb8-3655-4643-ac3a-b662d3f26b6b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-15
-- Tags: attack.defense-impairment, attack.t1685, attack.impact, attack.t1489
-- Description: Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services on Linux systems.
-- Attackers may stop or disable security tools and services to evade detection, maintain persistence, or disrupt system operations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*/service" OR Image="*/systemctl" OR Image="*/chkconfig") AND (CommandLine LIKE '% stop %' OR CommandLine LIKE '% disable %')) AND NOT (((Image="*/systemctl" AND (CommandLine LIKE '%--no-reload disable snap-snapd-%' OR CommandLine LIKE '% stop snap-snapd-%')) OR (Image="*/systemctl" AND ParentCommandLine LIKE '%tmp.ci/preinst upgrade%' AND (CommandLine LIKE '% stop %' AND CommandLine LIKE '%ssh.%')) OR (ParentCommandLine LIKE '%/dpkg/info/ubuntu-pro-client.prerm upgrade%' AND Image="*/systemctl"))) AND NOT ((Image="*/systemctl" AND CommandLine="*snap.amazon-ssm-agent.amazon-ssm-agent.service")))
