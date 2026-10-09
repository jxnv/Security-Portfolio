-- Title: Suspicious Package Installed - Linux
-- ID: 700fb7e8-2981-401c-8430-be58e189e741
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-03
-- Tags: attack.defense-impairment, attack.t1553.004
-- Description: Detects installation of suspicious packages using system installation utilities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*/apt" OR Image="*/apt-get") AND CommandLine LIKE '%install%') OR (Image="*/dpkg" AND (CommandLine LIKE '%--install%' OR CommandLine LIKE '%-i%')) OR (Image="*/rpm" AND CommandLine LIKE '%-i%') OR (Image="*/yum" AND (CommandLine LIKE '%localinstall%' OR CommandLine LIKE '%install%'))) AND ((CommandLine LIKE '%nmap%' OR CommandLine LIKE '% nc%' OR CommandLine LIKE '%netcat%' OR CommandLine LIKE '%wireshark%' OR CommandLine LIKE '%tshark%' OR CommandLine LIKE '%openconnect%' OR CommandLine LIKE '%proxychains%' OR CommandLine LIKE '%socat%')))
