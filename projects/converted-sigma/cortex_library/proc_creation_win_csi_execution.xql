// Title: Suspicious Csi.exe Usage
// ID: 40b95d31-1afc-469e-8d34-9a3a667d058e
// Status: test
// Level: medium
// Author: Konstantin Grishchenko, oscd.community
// Date: 2020-10-17
// Tags: attack.lateral-movement, attack.execution, attack.stealth, attack.t1072, attack.t1218
// Description: Csi.exe is a signed binary from Microsoft that comes with Visual Studio and provides C# interactive capabilities. It can be used to run C# code from a file passed as a parameter in command line. Early version of this utility provided with Microsoft “Roslyn” Community Technology Preview was named 'rcsi.exe'
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Company = "Microsoft Corporation") and (((action_process_image_path endswith "\\csi.exe" or action_process_image_path endswith "\\rcsi.exe")) or ((action_process_image_name = "csi.exe" or action_process_image_name = "rcsi.exe"))))
