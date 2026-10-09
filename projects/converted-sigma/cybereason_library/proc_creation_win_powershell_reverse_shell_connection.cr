// Title: Potential Powershell ReverseShell Connection
// ID: edc2f8ae-2412-4dfd-b9d5-0c57727e70be
// Status: stable
// Level: high
// Author: FPT.EagleEye, wagga, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-03-03
// Tags: attack.execution, attack.t1059.001
// Description: Detects usage of the "TcpClient" class. Which can be abused to establish remote connections and reverse-shells. As seen used by the Nishang "Invoke-PowerShellTcpOneLine" reverse shell and other.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " Net.Sockets.TCPClient" AND CommandLine contains ".GetStream(" AND CommandLine contains ".Write(")) AND (((OriginalFileName == "PowerShell.EXE" OR OriginalFileName == "pwsh.dll")) OR ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe"))))
