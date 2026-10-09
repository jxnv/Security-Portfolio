// Title: NtdllPipe Like Activity Execution
// ID: bbc865e4-7fcd-45a6-8ff1-95ced28ec5b2
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-05
// Tags: attack.defense-impairment
// Description: Detects command that type the content of ntdll.dll to a different file or a pipe in order to evade AV / EDR detection. As seen being used in the POC NtdllPipe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "type %windir%\\system32\\ntdll.dll" or action_process_image_command_line contains "type %systemroot%\\system32\\ntdll.dll" or action_process_image_command_line contains "type c:\\windows\\system32\\ntdll.dll" or action_process_image_command_line contains "\\\\ntdll.dll > \\\\\\\\.\\\\pipe\\\\"))
