// Title: Potential Azure Browser SSO Abuse
// ID: 50f852e6-af22-4c78-9ede-42ef36aa3453
// Status: test
// Level: low
// Author: Den Iuzvyk
// Date: 2020-07-15
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects abusing Azure Browser SSO by requesting OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser.
// An attacker can use this to authenticate to Azure AD in a browser as that user.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded = "C:\\Windows\\System32\\MicrosoftAccountTokenProvider.dll") and not (((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\") and action_process_image_path endswith "\\BackgroundTaskHost.exe")) and not ((((action_process_image_path startswith "C:\\Program Files\\Microsoft Visual Studio\\" or action_process_image_path startswith "C:\\Program Files (x86)\\Microsoft Visual Studio\\") and action_process_image_path endswith "\\IDE\\devenv.exe") or ((action_process_image_path startswith "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\") or (action_process_image_path endswith "\\WindowsApps\\MicrosoftEdge.exe") or ((action_process_image_path = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" or action_process_image_path = "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) or ((action_process_image_path startswith "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or action_process_image_path startswith "C:\\Program Files\\Microsoft\\EdgeCore\\") and (action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\msedgewebview2.exe")) or ((action_process_image_path = "C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" or action_process_image_path = "C:\\Program Files\\Internet Explorer\\iexplore.exe")) or (action_process_image_path = null) or (action_process_image_path endswith "\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"))))
