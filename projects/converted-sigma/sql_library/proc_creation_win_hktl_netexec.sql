-- Title: HackTool - NetExec Execution
-- ID: 7638e5fe-600c-4289-a968-f49dd537ec7d
-- Status: experimental
-- Level: high
-- Author: Chirag Damani
-- Date: 2026-03-29
-- Tags: attack.discovery, attack.t1018, attack.lateral-movement, attack.t1021
-- Description: Detects execution of the hacktool NetExec.
-- NetExec (formerly CrackMapExec) is a widely used post-exploitation tool designed for Active Directory penetration testing and network enumeration
-- In enterprise environments, the use of NetExec is considered suspicious or potentially malicious because it enables attackers to enumerate hosts, exploit network services, and move laterally across systems.
-- Threat actors and red teams commonly use NetExec to identify vulnerable systems, harvest credentials, and execute commands remotely.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%\\nxc.exe' AND (CommandLine ILIKE '% ftp %' OR CommandLine ILIKE '% ldap %' OR CommandLine ILIKE '% mssql %' OR CommandLine ILIKE '% nfs %' OR CommandLine ILIKE '% rdp %' OR CommandLine ILIKE '% smb %' OR CommandLine ILIKE '% ssh %' OR CommandLine ILIKE '% vnc %' OR CommandLine ILIKE '% winrm %' OR CommandLine ILIKE '% wmi %'))
