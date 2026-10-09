-- Title: Potential Remote Desktop Tunneling
-- ID: 8a3038e8-9c9d-46f8-b184-66234a160f6f
-- Status: test
-- Level: medium
-- Author: Tim Rauch, Elastic (idea)
-- Date: 2022-09-27
-- Tags: attack.lateral-movement, attack.t1021
-- Description: Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%:3389%') AND ((CommandLine ILIKE '% -L %' OR CommandLine ILIKE '% -P %' OR CommandLine ILIKE '% -R %' OR CommandLine ILIKE '% -pw %' OR CommandLine ILIKE '% -ssh %')))
