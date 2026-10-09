-- Title: PowerShell Base64 Encoded IEX Cmdlet
-- ID: 88f680b8-070e-402c-ae11-d2914f2257f1
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-08-23
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects usage of a base64 encoded "IEX" cmdlet in a process command line
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%SUVYIChb%' OR CommandLine ILIKE '%lFWCAoW%' OR CommandLine ILIKE '%JRVggKF%' OR CommandLine ILIKE '%aWV4IChb%' OR CommandLine ILIKE '%lleCAoW%' OR CommandLine ILIKE '%pZXggKF%' OR CommandLine ILIKE '%aWV4IChOZX%' OR CommandLine ILIKE '%lleCAoTmV3%' OR CommandLine ILIKE '%pZXggKE5ld%' OR CommandLine ILIKE '%SUVYIChOZX%' OR CommandLine ILIKE '%lFWCAoTmV3%' OR CommandLine ILIKE '%JRVggKE5ld%' OR CommandLine ILIKE '%SUVYKF%' OR CommandLine ILIKE '%lFWChb%' OR CommandLine ILIKE '%JRVgoW%' OR CommandLine ILIKE '%aWV4KF%' OR CommandLine ILIKE '%lleChb%' OR CommandLine ILIKE '%pZXgoW%' OR CommandLine ILIKE '%aWV4KE5ld%' OR CommandLine ILIKE '%lleChOZX%' OR CommandLine ILIKE '%pZXgoTmV3%' OR CommandLine ILIKE '%SUVYKE5ld%' OR CommandLine ILIKE '%lFWChOZX%' OR CommandLine ILIKE '%JRVgoTmV3%' OR CommandLine ILIKE '%SUVYKCgn%' OR CommandLine ILIKE '%lFWCgoJ%' OR CommandLine ILIKE '%JRVgoKC%' OR CommandLine ILIKE '%aWV4KCgn%' OR CommandLine ILIKE '%lleCgoJ%' OR CommandLine ILIKE '%pZXgoKC%')) OR ((CommandLine ILIKE '%SQBFAFgAIAAoAFsA%' OR CommandLine ILIKE '%kARQBYACAAKABbA%' OR CommandLine ILIKE '%JAEUAWAAgACgAWw%' OR CommandLine ILIKE '%aQBlAHgAIAAoAFsA%' OR CommandLine ILIKE '%kAZQB4ACAAKABbA%' OR CommandLine ILIKE '%pAGUAeAAgACgAWw%' OR CommandLine ILIKE '%aQBlAHgAIAAoAE4AZQB3A%' OR CommandLine ILIKE '%kAZQB4ACAAKABOAGUAdw%' OR CommandLine ILIKE '%pAGUAeAAgACgATgBlAHcA%' OR CommandLine ILIKE '%SQBFAFgAIAAoAE4AZQB3A%' OR CommandLine ILIKE '%kARQBYACAAKABOAGUAdw%' OR CommandLine ILIKE '%JAEUAWAAgACgATgBlAHcA%')))
