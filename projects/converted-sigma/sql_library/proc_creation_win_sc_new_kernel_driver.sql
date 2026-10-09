-- Title: New Kernel Driver Via SC.EXE
-- ID: 431a1fdb-4799-4f3b-91c3-a683b003fc49
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-14
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
-- Description: Detects creation of a new service (kernel driver) with the type "kernel"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\sc.exe' AND (CommandLine ILIKE '%create%' OR CommandLine ILIKE '%config%') AND (CommandLine ILIKE '%binPath%' AND CommandLine ILIKE '%type%' AND CommandLine ILIKE '%kernel%')) AND NOT ((((CommandLine ILIKE '%create netprotection_network_filter%' AND CommandLine ILIKE '%type= kernel start= %' AND CommandLine ILIKE '%binPath= System32\\drivers\\netprotection_network_filter%' AND CommandLine ILIKE '%DisplayName= netprotection_network_filter%' AND CommandLine ILIKE '%group= PNP_TDI tag= yes%')) OR ((CommandLine ILIKE '%create avelam binpath=C:\\Windows\\system32\\drivers\\avelam.sys%' AND CommandLine ILIKE '%type=kernel start=boot error=critical group=Early-Launch%')))))
