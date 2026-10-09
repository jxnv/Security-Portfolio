-- Title: Triple Cross eBPF Rootkit Install Commands
-- ID: 22236d75-d5a0-4287-bf06-c93b1770860f
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-05
-- Tags: attack.stealth, attack.t1014
-- Description: Detects default install commands of the Triple Cross eBPF rootkit based on the "deployer.sh" script
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*/sudo" AND (CommandLine LIKE '% tc %' AND CommandLine LIKE '% enp0s3 %') AND (CommandLine LIKE '% qdisc %' OR CommandLine LIKE '% filter %'))
