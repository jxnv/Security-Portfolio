-- Title: Network Connection Initiated To BTunnels Domains
-- ID: 9e02c8ec-02b9-43e8-81eb-34a475ba7965
-- Status: test
-- Level: medium
-- Author: Kamran Saifullah
-- Date: 2024-09-13
-- Tags: attack.exfiltration, attack.command-and-control, attack.t1567, attack.t1572
-- Description: Detects network connections to BTunnels domains initiated by a process on the system.
-- Attackers can abuse that feature to establish a reverse shell or persistence on a machine.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Initiated = 'true' AND DestinationHostname ILIKE '%.btunnel.co.in')
