// Title: Kubernetes Potential Enumeration Activity
// ID: 597a7e84-187d-458b-9e4f-2f5a0e676711
// Status: experimental
// Level: medium
// Author: uniqu3-us3r
// Date: 2026-04-28
// Tags: attack.execution, attack.discovery, attack.t1609, attack.t1613
// Description: Detects potential Kubernetes enumeration or attack activity via the audit log.
// This includes the execution of common shells, utilities, or specialized tools like 'Rakkess' (access_matrix) and 'TruffleHog' via Kubernetes API requests.
// Attackers use these methods to perform reconnaissance (enumeration), secret harvesting, or execute code (exec) within a cluster.
// Converted by: Sigma Universal SIEM/EDR CLI

((responseStatus.code == "ALLOW") AND (((requestURI contains "%2fbin%2fash" OR requestURI contains "%2fbin%2fbash" OR requestURI contains "%2fbin%2fbusybox" OR requestURI contains "%2fbin%2fdash" OR requestURI contains "%2fbin%2fsh" OR requestURI contains "%2fbin%2fzsh" OR requestURI contains "/bin/ash" OR requestURI contains "/bin/bash" OR requestURI contains "/bin/busybox" OR requestURI contains "/bin/dash" OR requestURI contains "/bin/sh" OR requestURI contains "/bin/zsh" OR requestURI contains "%2fusr%2fbin%2fcurl" OR requestURI contains "%2fusr%2fbin%2fkubectl" OR requestURI contains "%2fusr%2fbin%2fperl" OR requestURI contains "%2fusr%2fbin%2fpython" OR requestURI contains "%2fusr%2fbin%2fwget" OR requestURI contains "/usr/bin/curl" OR requestURI contains "/usr/bin/kubectl" OR requestURI contains "/usr/bin/perl" OR requestURI contains "/usr/bin/python" OR requestURI contains "/usr/bin/wget")) OR ((userAgent contains "access_matrix" OR userAgent contains "trufflehog" OR userAgent contains "azurehound" OR userAgent contains "micro-scanner"))))
