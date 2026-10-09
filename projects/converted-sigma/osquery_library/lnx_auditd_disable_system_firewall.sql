-- Title: Disable System Firewall
-- ID: 53059bc0-1472-438b-956a-7508a94a91f0
-- Status: test
-- Level: high
-- Author: Pawel Mazur
-- Date: 2022-01-22
-- Tags: attack.defense-impairment, attack.t1686
-- Description: Detects disabling of system firewalls which could be used by adversaries to bypass controls that limit usage of the network.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (type = 'SERVICE_STOP' AND (unit = 'firewalld' OR unit = 'iptables' OR unit = 'ufw'))
