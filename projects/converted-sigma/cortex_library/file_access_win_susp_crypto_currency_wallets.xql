// Title: Access To Crypto Currency Wallets By Uncommon Applications
// ID: f41b0311-44f9-44f0-816d-dd45e39d4bc8
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2024-07-29
// Tags: attack.t1003, attack.credential-access
// Description: Detects file access requests to crypto currency files by uncommon processes.
// Could indicate potential attempt of crypto currency wallet stealing.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((FileName contains "\\AppData\\Roaming\\Ethereum\\keystore\\" or FileName contains "\\AppData\\Roaming\\EthereumClassic\\keystore\\" or FileName contains "\\AppData\\Roaming\\monero\\wallets\\")) or ((FileName endswith "\\AppData\\Roaming\\Bitcoin\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\BitcoinABC\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\BitcoinSV\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\DashCore\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\DogeCoin\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\Litecoin\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\Ripple\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\Zcash\\wallet.dat"))) and not ((((action_process_image_path startswith "C:\\Program Files (x86)\\" or action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Windows\\system32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\")) or (action_process_image_path = "System"))) and not ((action_process_image_path startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\" and (action_process_image_path endswith "\\MpCopyAccelerator.exe" or action_process_image_path endswith "\\MsMpEng.exe"))))
