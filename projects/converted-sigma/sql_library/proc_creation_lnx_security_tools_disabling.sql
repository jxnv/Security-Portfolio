-- Title: Disabling Security Tools
-- ID: e3a8a052-111f-4606-9aee-f28ebeb76776
-- Status: test
-- Level: medium
-- Author: Ömer Günal, Alejandro Ortuno, oscd.community
-- Date: 2020-06-17
-- Tags: attack.defense-impairment, attack.t1686
-- Description: Detects disabling security tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%/service' AND (CommandLine ILIKE '%cbdaemon%' AND CommandLine ILIKE '%stop%')) OR (Image ILIKE '%/chkconfig' AND (CommandLine ILIKE '%cbdaemon%' AND CommandLine ILIKE '%off%')) OR (Image ILIKE '%/systemctl' AND (CommandLine ILIKE '%cbdaemon%' AND CommandLine ILIKE '%stop%')) OR (Image ILIKE '%/systemctl' AND (CommandLine ILIKE '%cbdaemon%' AND CommandLine ILIKE '%disable%')) OR (Image ILIKE '%/systemctl' AND (CommandLine ILIKE '%stop%' AND CommandLine ILIKE '%falcon-sensor%')) OR (Image ILIKE '%/systemctl' AND (CommandLine ILIKE '%disable%' AND CommandLine ILIKE '%falcon-sensor%')) OR (Image ILIKE '%/systemctl' AND (CommandLine ILIKE '%firewalld%' AND CommandLine ILIKE '%stop%')) OR (Image ILIKE '%/systemctl' AND (CommandLine ILIKE '%firewalld%' AND CommandLine ILIKE '%disable%')) OR (Image ILIKE '%/service' AND (CommandLine ILIKE '%iptables%' AND CommandLine ILIKE '%stop%')) OR (Image ILIKE '%/service' AND (CommandLine ILIKE '%ip6tables%' AND CommandLine ILIKE '%stop%')) OR (Image ILIKE '%/chkconfig' AND (CommandLine ILIKE '%iptables%' AND CommandLine ILIKE '%stop%')) OR (Image ILIKE '%/chkconfig' AND (CommandLine ILIKE '%ip6tables%' AND CommandLine ILIKE '%stop%')) OR (Image ILIKE '%/setenforce' AND CommandLine ILIKE '%0%'))
