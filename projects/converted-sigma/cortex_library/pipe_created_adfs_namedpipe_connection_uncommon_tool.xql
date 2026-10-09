// Title: ADFS Database Named Pipe Connection By Uncommon Tool
// ID: 1ea13e8c-03ea-409b-877d-ce5c3d2c1cb3
// Status: test
// Level: medium
// Author: Roberto Rodriguez @Cyb3rWard0g
// Date: 2021-10-08
// Tags: attack.collection, attack.t1005
// Description: Detects suspicious local connections via a named pipe to the AD FS configuration database (Windows Internal Database).
// Used to access information such as the AD FS configuration settings which contains sensitive information used to sign SAML tokens.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((PipeName = "\\MICROSOFT##WID\\tsql\\query") and not (((action_process_image_path endswith ":\\Windows\\System32\\mmc.exe" or action_process_image_path endswith ":\\Windows\\system32\\svchost.exe" or action_process_image_path endswith ":\\Windows\\System32\\wsmprovhost.exe" or action_process_image_path endswith ":\\Windows\\SysWOW64\\mmc.exe" or action_process_image_path endswith ":\\Windows\\SysWOW64\\wsmprovhost.exe" or action_process_image_path endswith ":\\Windows\\WID\\Binn\\sqlwriter.exe" or action_process_image_path endswith "\\AzureADConnect.exe" or action_process_image_path endswith "\\Microsoft.Identity.Health.Adfs.PshSurrogate.exe" or action_process_image_path endswith "\\Microsoft.IdentityServer.ServiceHost.exe" or action_process_image_path endswith "\\Microsoft.Tri.Sensor.exe" or action_process_image_path endswith "\\sqlservr.exe" or action_process_image_path endswith "\\tssdis.exe"))))
