// Title: Taskkill Symantec Endpoint Protection
// ID: 4a6713f6-3331-11ed-a261-0242ac120002
// Status: test
// Level: high
// Author: Ilya Krestinichev, Florian Roth (Nextron Systems)
// Date: 2022-09-13
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects one of the possible scenarios for disabling Symantec Endpoint Protection.
// Symantec Endpoint Protection antivirus software services incorrectly implement the protected service mechanism.
// As a result, the NT AUTHORITY/SYSTEM user can execute the taskkill /im command several times ccSvcHst.exe /f, thereby killing the process belonging to the service, and thus shutting down the service.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "taskkill" and action_process_image_command_line contains " /F " and action_process_image_command_line contains " /IM " and action_process_image_command_line contains "ccSvcHst.exe"))
