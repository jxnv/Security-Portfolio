// Title: BITS Transfer Job Download From Direct IP
// ID: 90f138c1-f578-4ac3-8c49-eecfd847c8b7
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-11
// Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197
// Description: Detects a BITS transfer job downloading file(s) from a direct IP address.
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID == "16403" AND (RemoteName contains "http://1" OR RemoteName contains "http://2" OR RemoteName contains "http://3" OR RemoteName contains "http://4" OR RemoteName contains "http://5" OR RemoteName contains "http://6" OR RemoteName contains "http://7" OR RemoteName contains "http://8" OR RemoteName contains "http://9" OR RemoteName contains "https://1" OR RemoteName contains "https://2" OR RemoteName contains "https://3" OR RemoteName contains "https://4" OR RemoteName contains "https://5" OR RemoteName contains "https://6" OR RemoteName contains "https://7" OR RemoteName contains "https://8" OR RemoteName contains "https://9")) AND NOT ((((RemoteName contains "://10." OR RemoteName contains "://192.168." OR RemoteName contains "://172.16." OR RemoteName contains "://172.17." OR RemoteName contains "://172.18." OR RemoteName contains "://172.19." OR RemoteName contains "://172.20." OR RemoteName contains "://172.21." OR RemoteName contains "://172.22." OR RemoteName contains "://172.23." OR RemoteName contains "://172.24." OR RemoteName contains "://172.25." OR RemoteName contains "://172.26." OR RemoteName contains "://172.27." OR RemoteName contains "://172.28." OR RemoteName contains "://172.29." OR RemoteName contains "://172.30." OR RemoteName contains "://172.31." OR RemoteName contains "://127." OR RemoteName contains "://169.254.")) OR ((RemoteName contains "https://7-" OR RemoteName contains "http://7-")))))
