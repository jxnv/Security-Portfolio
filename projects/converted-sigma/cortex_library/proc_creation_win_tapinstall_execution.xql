// Title: Tap Installer Execution
// ID: 99793437-3e16-439b-be0f-078782cf953d
// Status: test
// Level: medium
// Author: Daniil Yugoslavskiy, Ian Davis, oscd.community
// Date: 2019-10-24
// Tags: attack.exfiltration, attack.t1048
// Description: Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\tapinstall.exe") and not ((((action_process_image_path contains ":\\Program Files\\Avast Software\\SecureLine VPN\\" or action_process_image_path contains ":\\Program Files (x86)\\Avast Software\\SecureLine VPN\\")) or (action_process_image_path contains ":\\Program Files\\OpenVPN Connect\\drivers\\tap\\") or (action_process_image_path contains ":\\Program Files (x86)\\Proton Technologies\\ProtonVPNTap\\installer\\"))))
