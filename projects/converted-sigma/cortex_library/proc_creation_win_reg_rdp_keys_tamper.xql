// Title: Potential Tampering With RDP Related Registry Keys Via Reg.EXE
// ID: 0d5675be-bc88-4172-86d3-1e96a4476536
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), @Kostastsale, TheDFIRReport
// Date: 2022-02-12
// Tags: attack.persistence, attack.lateral-movement, attack.defense-impairment, attack.t1021.001, attack.t1112
// Description: Detects the execution of "reg.exe" for enabling/disabling the RDP service on the host by tampering with the 'CurrentControlSet\Control\Terminal Server' values
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " add " and action_process_image_command_line contains "\\CurrentControlSet\\Control\\Terminal Server" and action_process_image_command_line contains "REG_DWORD" and action_process_image_command_line contains " /f")) and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe"))) and (((action_process_image_command_line contains "Licensing Core" and action_process_image_command_line contains "EnableConcurrentSessions")) or ((action_process_image_command_line contains "AllowTSConnections" or action_process_image_command_line contains "fDenyTSConnections" or action_process_image_command_line contains "fEnableWinStation" or action_process_image_command_line contains "fSingleSessionPerUser" or action_process_image_command_line contains "IdleWinStationPoolCount" or action_process_image_command_line contains "MaxInstanceCount" or action_process_image_command_line contains "SecurityLayer" or action_process_image_command_line contains "TSAdvertise" or action_process_image_command_line contains "TSAppCompat" or action_process_image_command_line contains "TSEnabled" or action_process_image_command_line contains "TSUserEnabled" or action_process_image_command_line contains "WinStations\\RDP-Tcp"))) and not (((action_process_image_command_line contains "SecurityLayer" and action_process_image_command_line contains "02"))))
