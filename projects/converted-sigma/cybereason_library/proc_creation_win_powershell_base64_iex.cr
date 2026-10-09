// Title: PowerShell Base64 Encoded IEX Cmdlet
// ID: 88f680b8-070e-402c-ae11-d2914f2257f1
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-08-23
// Tags: attack.execution, attack.t1059.001
// Description: Detects usage of a base64 encoded "IEX" cmdlet in a process command line
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "SUVYIChb" OR CommandLine contains "lFWCAoW" OR CommandLine contains "JRVggKF" OR CommandLine contains "aWV4IChb" OR CommandLine contains "lleCAoW" OR CommandLine contains "pZXggKF" OR CommandLine contains "aWV4IChOZX" OR CommandLine contains "lleCAoTmV3" OR CommandLine contains "pZXggKE5ld" OR CommandLine contains "SUVYIChOZX" OR CommandLine contains "lFWCAoTmV3" OR CommandLine contains "JRVggKE5ld" OR CommandLine contains "SUVYKF" OR CommandLine contains "lFWChb" OR CommandLine contains "JRVgoW" OR CommandLine contains "aWV4KF" OR CommandLine contains "lleChb" OR CommandLine contains "pZXgoW" OR CommandLine contains "aWV4KE5ld" OR CommandLine contains "lleChOZX" OR CommandLine contains "pZXgoTmV3" OR CommandLine contains "SUVYKE5ld" OR CommandLine contains "lFWChOZX" OR CommandLine contains "JRVgoTmV3" OR CommandLine contains "SUVYKCgn" OR CommandLine contains "lFWCgoJ" OR CommandLine contains "JRVgoKC" OR CommandLine contains "aWV4KCgn" OR CommandLine contains "lleCgoJ" OR CommandLine contains "pZXgoKC")) OR ((CommandLine contains "SQBFAFgAIAAoAFsA" OR CommandLine contains "kARQBYACAAKABbA" OR CommandLine contains "JAEUAWAAgACgAWw" OR CommandLine contains "aQBlAHgAIAAoAFsA" OR CommandLine contains "kAZQB4ACAAKABbA" OR CommandLine contains "pAGUAeAAgACgAWw" OR CommandLine contains "aQBlAHgAIAAoAE4AZQB3A" OR CommandLine contains "kAZQB4ACAAKABOAGUAdw" OR CommandLine contains "pAGUAeAAgACgATgBlAHcA" OR CommandLine contains "SQBFAFgAIAAoAE4AZQB3A" OR CommandLine contains "kARQBYACAAKABOAGUAdw" OR CommandLine contains "JAEUAWAAgACgATgBlAHcA")))
