-- Title: Disabling Security Tools
-- ID: e3a8a052-111f-4606-9aee-f28ebeb76776
-- Status: test
-- Level: medium
-- Author: Ömer Günal, Alejandro Ortuno, oscd.community
-- Date: 2020-06-17
-- Tags: attack.defense-impairment, attack.t1686
-- Description: Detects disabling security tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/service" AND (CommandLine LIKE '%cbdaemon%' AND CommandLine LIKE '%stop%')) OR (Image="*/chkconfig" AND (CommandLine LIKE '%cbdaemon%' AND CommandLine LIKE '%off%')) OR (Image="*/systemctl" AND (CommandLine LIKE '%cbdaemon%' AND CommandLine LIKE '%stop%')) OR (Image="*/systemctl" AND (CommandLine LIKE '%cbdaemon%' AND CommandLine LIKE '%disable%')) OR (Image="*/systemctl" AND (CommandLine LIKE '%stop%' AND CommandLine LIKE '%falcon-sensor%')) OR (Image="*/systemctl" AND (CommandLine LIKE '%disable%' AND CommandLine LIKE '%falcon-sensor%')) OR (Image="*/systemctl" AND (CommandLine LIKE '%firewalld%' AND CommandLine LIKE '%stop%')) OR (Image="*/systemctl" AND (CommandLine LIKE '%firewalld%' AND CommandLine LIKE '%disable%')) OR (Image="*/service" AND (CommandLine LIKE '%iptables%' AND CommandLine LIKE '%stop%')) OR (Image="*/service" AND (CommandLine LIKE '%ip6tables%' AND CommandLine LIKE '%stop%')) OR (Image="*/chkconfig" AND (CommandLine LIKE '%iptables%' AND CommandLine LIKE '%stop%')) OR (Image="*/chkconfig" AND (CommandLine LIKE '%ip6tables%' AND CommandLine LIKE '%stop%')) OR (Image="*/setenforce" AND CommandLine LIKE '%0%'))
