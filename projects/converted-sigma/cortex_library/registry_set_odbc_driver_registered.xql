// Title: New ODBC Driver Registered
// ID: 3390fbef-c98d-4bdd-a863-d65ed7c610dd
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-23
// Tags: attack.persistence
// Description: Detects the registration of a new ODBC driver.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\SOFTWARE\\ODBC\\ODBCINST.INI\\" and TargetObject endswith "\\Driver") and not ((TargetObject contains "\\SQL Server\\" and Details = "%WINDIR%\\System32\\SQLSRV32.dll")) and not (((TargetObject contains "\\Microsoft Access " and Details startswith "C:\\Progra" and Details endswith "\\ACEODBC.DLL") or (TargetObject contains "\\Microsoft Excel Driver" and Details startswith "C:\\Progra" and Details endswith "\\ACEODBC.DLL"))))
