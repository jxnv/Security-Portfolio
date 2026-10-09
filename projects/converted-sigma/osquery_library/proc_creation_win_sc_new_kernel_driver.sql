-- Title: New Kernel Driver Via SC.EXE
-- ID: 431a1fdb-4799-4f3b-91c3-a683b003fc49
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-14
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
-- Description: Detects creation of a new service (kernel driver) with the type "kernel"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\sc.exe" AND (CommandLine LIKE '%create%' OR CommandLine LIKE '%config%') AND (CommandLine LIKE '%binPath%' AND CommandLine LIKE '%type%' AND CommandLine LIKE '%kernel%')) AND NOT ((((CommandLine LIKE '%create netprotection_network_filter%' AND CommandLine LIKE '%type= kernel start= %' AND CommandLine LIKE '%binPath= System32\\drivers\\netprotection_network_filter%' AND CommandLine LIKE '%DisplayName= netprotection_network_filter%' AND CommandLine LIKE '%group= PNP_TDI tag= yes%')) OR ((CommandLine LIKE '%create avelam binpath=C:\\Windows\\system32\\drivers\\avelam.sys%' AND CommandLine LIKE '%type=kernel start=boot error=critical group=Early-Launch%')))))
