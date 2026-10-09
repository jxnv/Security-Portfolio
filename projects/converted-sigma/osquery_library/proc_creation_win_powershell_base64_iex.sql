-- Title: PowerShell Base64 Encoded IEX Cmdlet
-- ID: 88f680b8-070e-402c-ae11-d2914f2257f1
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-08-23
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects usage of a base64 encoded "IEX" cmdlet in a process command line
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%SUVYIChb%' OR CommandLine LIKE '%lFWCAoW%' OR CommandLine LIKE '%JRVggKF%' OR CommandLine LIKE '%aWV4IChb%' OR CommandLine LIKE '%lleCAoW%' OR CommandLine LIKE '%pZXggKF%' OR CommandLine LIKE '%aWV4IChOZX%' OR CommandLine LIKE '%lleCAoTmV3%' OR CommandLine LIKE '%pZXggKE5ld%' OR CommandLine LIKE '%SUVYIChOZX%' OR CommandLine LIKE '%lFWCAoTmV3%' OR CommandLine LIKE '%JRVggKE5ld%' OR CommandLine LIKE '%SUVYKF%' OR CommandLine LIKE '%lFWChb%' OR CommandLine LIKE '%JRVgoW%' OR CommandLine LIKE '%aWV4KF%' OR CommandLine LIKE '%lleChb%' OR CommandLine LIKE '%pZXgoW%' OR CommandLine LIKE '%aWV4KE5ld%' OR CommandLine LIKE '%lleChOZX%' OR CommandLine LIKE '%pZXgoTmV3%' OR CommandLine LIKE '%SUVYKE5ld%' OR CommandLine LIKE '%lFWChOZX%' OR CommandLine LIKE '%JRVgoTmV3%' OR CommandLine LIKE '%SUVYKCgn%' OR CommandLine LIKE '%lFWCgoJ%' OR CommandLine LIKE '%JRVgoKC%' OR CommandLine LIKE '%aWV4KCgn%' OR CommandLine LIKE '%lleCgoJ%' OR CommandLine LIKE '%pZXgoKC%')) OR ((CommandLine LIKE '%SQBFAFgAIAAoAFsA%' OR CommandLine LIKE '%kARQBYACAAKABbA%' OR CommandLine LIKE '%JAEUAWAAgACgAWw%' OR CommandLine LIKE '%aQBlAHgAIAAoAFsA%' OR CommandLine LIKE '%kAZQB4ACAAKABbA%' OR CommandLine LIKE '%pAGUAeAAgACgAWw%' OR CommandLine LIKE '%aQBlAHgAIAAoAE4AZQB3A%' OR CommandLine LIKE '%kAZQB4ACAAKABOAGUAdw%' OR CommandLine LIKE '%pAGUAeAAgACgATgBlAHcA%' OR CommandLine LIKE '%SQBFAFgAIAAoAE4AZQB3A%' OR CommandLine LIKE '%kARQBYACAAKABOAGUAdw%' OR CommandLine LIKE '%JAEUAWAAgACgATgBlAHcA%')))
