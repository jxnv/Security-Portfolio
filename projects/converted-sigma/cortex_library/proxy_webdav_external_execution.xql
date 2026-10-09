// Title: Suspicious External WebDAV Execution
// ID: 1ae64f96-72b6-48b3-ad3d-e71dff6c6398
// Status: test
// Level: high
// Author: Ahmed Farouk
// Date: 2024-05-10
// Tags: attack.initial-access, attack.resource-development, attack.t1584, attack.t1566
// Description: Detects executables launched from external WebDAV shares using the WebDAV Explorer integration, commonly seen in initial access campaigns.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((c-uri endswith ".7z" or c-uri endswith ".bat" or c-uri endswith ".dat" or c-uri endswith ".cmd" or c-uri endswith ".exe" or c-uri endswith ".js" or c-uri endswith ".lnk" or c-uri endswith ".ps1" or c-uri endswith ".rar" or c-uri endswith ".url" or c-uri endswith ".vbe" or c-uri endswith ".vbs" or c-uri endswith ".zip")) and (c-useragent startswith "Microsoft-WebDAV-MiniRedir/" and cs-method = "GET")) and not (((incidr(dst_ip, "127.0.0.0/8") or incidr(dst_ip, "10.0.0.0/8") or incidr(dst_ip, "172.16.0.0/12") or incidr(dst_ip, "192.168.0.0/16") or incidr(dst_ip, "169.254.0.0/16") or incidr(dst_ip, "::1/128") or incidr(dst_ip, "fe80::/10") or incidr(dst_ip, "fc00::/7")))))
