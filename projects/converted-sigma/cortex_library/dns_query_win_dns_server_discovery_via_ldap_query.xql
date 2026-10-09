// Title: DNS Server Discovery Via LDAP Query
// ID: a21bcd7e-38ec-49ad-b69a-9ea17e69509e
// Status: test
// Level: low
// Author: frack113
// Date: 2022-08-20
// Tags: attack.discovery, attack.t1482
// Description: Detects DNS server discovery via LDAP query requests from uncommon applications
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((QueryName startswith "_ldap.") and not (((action_process_image_path contains ":\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" and action_process_image_path endswith "\\MsMpEng.exe") or ((action_process_image_path contains ":\\Program Files\\" or action_process_image_path contains ":\\Program Files (x86)\\" or action_process_image_path contains ":\\Windows\\")) or (action_process_image_path = null) or (action_process_image_path = "<unknown process>"))) and not (((action_process_image_path startswith "C:\\WindowsAzure\\GuestAgent") or ((action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\firefox.exe" or action_process_image_path endswith "\\opera.exe")))))
