// Title: Usage of Renamed Sysinternals Tools - RegistrySet
// ID: 8023f872-3f1d-4301-a384-801889917ab4
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-24
// Tags: attack.resource-development, attack.t1588.002
// Description: Detects non-sysinternals tools setting the "accepteula" key which normally is set on sysinternals tool execution
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\PsExec" or TargetObject contains "\\ProcDump" or TargetObject contains "\\Handle" or TargetObject contains "\\LiveKd" or TargetObject contains "\\Process Explorer" or TargetObject contains "\\PsLoglist" or TargetObject contains "\\PsPasswd" or TargetObject contains "\\Active Directory Explorer") and TargetObject endswith "\\EulaAccepted") and not (((action_process_image_path endswith "\\PsExec.exe" or action_process_image_path endswith "\\PsExec64.exe" or action_process_image_path endswith "\\PsExec64a.exe" or action_process_image_path endswith "\\procdump.exe" or action_process_image_path endswith "\\procdump64.exe" or action_process_image_path endswith "\\procdump64a.exe" or action_process_image_path endswith "\\handle.exe" or action_process_image_path endswith "\\handle64.exe" or action_process_image_path endswith "\\handle64a.exe" or action_process_image_path endswith "\\livekd.exe" or action_process_image_path endswith "\\livekd64.exe" or action_process_image_path endswith "\\procexp.exe" or action_process_image_path endswith "\\procexp64.exe" or action_process_image_path endswith "\\procexp64a.exe" or action_process_image_path endswith "\\psloglist.exe" or action_process_image_path endswith "\\psloglist64.exe" or action_process_image_path endswith "\\psloglist64a.exe" or action_process_image_path endswith "\\pspasswd.exe" or action_process_image_path endswith "\\pspasswd64.exe" or action_process_image_path endswith "\\pspasswd64a.exe" or action_process_image_path endswith "\\ADExplorer.exe" or action_process_image_path endswith "\\ADExplorer64.exe" or action_process_image_path endswith "\\ADExplorer64a.exe"))) and not ((action_process_image_path = null)))
