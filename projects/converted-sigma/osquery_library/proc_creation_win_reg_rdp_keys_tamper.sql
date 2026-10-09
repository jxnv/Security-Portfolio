-- Title: Potential Tampering With RDP Related Registry Keys Via Reg.EXE
-- ID: 0d5675be-bc88-4172-86d3-1e96a4476536
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems), @Kostastsale, TheDFIRReport
-- Date: 2022-02-12
-- Tags: attack.persistence, attack.lateral-movement, attack.defense-impairment, attack.t1021.001, attack.t1112
-- Description: Detects the execution of "reg.exe" for enabling/disabling the RDP service on the host by tampering with the 'CurrentControlSet\Control\Terminal Server' values
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '% add %' AND CommandLine LIKE '%\\CurrentControlSet\\Control\\Terminal Server%' AND CommandLine LIKE '%REG_DWORD%' AND CommandLine LIKE '% /f%')) AND ((Image="*\\reg.exe") OR (OriginalFileName = 'reg.exe'))) AND (((CommandLine LIKE '%Licensing Core%' AND CommandLine LIKE '%EnableConcurrentSessions%')) OR ((CommandLine LIKE '%AllowTSConnections%' OR CommandLine LIKE '%fDenyTSConnections%' OR CommandLine LIKE '%fEnableWinStation%' OR CommandLine LIKE '%fSingleSessionPerUser%' OR CommandLine LIKE '%IdleWinStationPoolCount%' OR CommandLine LIKE '%MaxInstanceCount%' OR CommandLine LIKE '%SecurityLayer%' OR CommandLine LIKE '%TSAdvertise%' OR CommandLine LIKE '%TSAppCompat%' OR CommandLine LIKE '%TSEnabled%' OR CommandLine LIKE '%TSUserEnabled%' OR CommandLine LIKE '%WinStations\\RDP-Tcp%'))) AND NOT (((CommandLine LIKE '%SecurityLayer%' AND CommandLine LIKE '%02%'))))
