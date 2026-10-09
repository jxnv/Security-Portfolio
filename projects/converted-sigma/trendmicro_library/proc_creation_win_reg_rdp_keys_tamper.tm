// Title: Potential Tampering With RDP Related Registry Keys Via Reg.EXE
// ID: 0d5675be-bc88-4172-86d3-1e96a4476536
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), @Kostastsale, TheDFIRReport
// Date: 2022-02-12
// Tags: attack.persistence, attack.lateral-movement, attack.defense-impairment, attack.t1021.001, attack.t1112
// Description: Detects the execution of "reg.exe" for enabling/disabling the RDP service on the host by tampering with the 'CurrentControlSet\Control\Terminal Server' values
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine: "* add *" AND CommandLine: "*\\CurrentControlSet\\Control\\Terminal Server*" AND CommandLine: "*REG_DWORD*" AND CommandLine: "* /f*")) AND ((Image="*\\reg.exe") OR (OriginalFileName: "reg.exe"))) AND (((CommandLine: "*Licensing Core*" AND CommandLine: "*EnableConcurrentSessions*")) OR ((CommandLine: "*AllowTSConnections*" OR CommandLine: "*fDenyTSConnections*" OR CommandLine: "*fEnableWinStation*" OR CommandLine: "*fSingleSessionPerUser*" OR CommandLine: "*IdleWinStationPoolCount*" OR CommandLine: "*MaxInstanceCount*" OR CommandLine: "*SecurityLayer*" OR CommandLine: "*TSAdvertise*" OR CommandLine: "*TSAppCompat*" OR CommandLine: "*TSEnabled*" OR CommandLine: "*TSUserEnabled*" OR CommandLine: "*WinStations\\RDP-Tcp*"))) AND NOT (((CommandLine: "*SecurityLayer*" AND CommandLine: "*02*"))))
