// Title: Suspicious Windows Strings In URI
// ID: 9f6a34b4-2688-4eb7-a7f5-e39fef573d0e
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-06
// Tags: attack.persistence, attack.exfiltration, attack.t1505.003
// Description: Detects suspicious Windows strings in URI which could indicate possible exfiltration or webshell communication
// Converted by: Sigma Universal SIEM/EDR CLI

((cs-uri-query: "*=C:/Users*" OR cs-uri-query: "*=C:/Program%20Files*" OR cs-uri-query: "*=C:/Windows*" OR cs-uri-query: "*=C%3A%5CUsers*" OR cs-uri-query: "*=C%3A%5CProgram%20Files*" OR cs-uri-query: "*=C%3A%5CWindows*"))
