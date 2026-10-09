// Title: MSSQL XPCmdshell Suspicious Execution
// ID: 7f103213-a04e-4d59-8261-213dddf22314
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-12
// Tags: attack.execution
// Description: Detects when the MSSQL "xp_cmdshell" stored procedure is used to execute commands
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Provider_Name contains "MSSQL" and EventID = 33205 and (Data contains "object_name:xp_cmdshell" and Data contains "statement:EXEC"))
