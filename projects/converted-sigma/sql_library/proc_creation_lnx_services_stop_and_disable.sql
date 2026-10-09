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

SELECT * FROM security_logs WHERE (((Image ILIKE '%/service' OR Image ILIKE '%/systemctl' OR Image ILIKE '%/chkconfig') AND (CommandLine ILIKE '% stop %' OR CommandLine ILIKE '% disable %')) AND NOT (((Image ILIKE '%/systemctl' AND (CommandLine ILIKE '%--no-reload disable snap-snapd-%' OR CommandLine ILIKE '% stop snap-snapd-%')) OR (Image ILIKE '%/systemctl' AND ParentCommandLine ILIKE '%tmp.ci/preinst upgrade%' AND (CommandLine ILIKE '% stop %' AND CommandLine ILIKE '%ssh.%')) OR (ParentCommandLine ILIKE '%/dpkg/info/ubuntu-pro-client.prerm upgrade%' AND Image ILIKE '%/systemctl'))) AND NOT ((Image ILIKE '%/systemctl' AND CommandLine ILIKE '%snap.amazon-ssm-agent.amazon-ssm-agent.service')))
