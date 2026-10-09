// Title: PAExec Service Installation
// ID: de7ce410-b3fb-4e8a-b38c-3b999e2c3420
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-26
// Tags: attack.execution, attack.t1569.002
// Description: Detects PAExec service installation
// Converted by: Sigma Universal SIEM/EDR CLI

((Provider_Name == "Service Control Manager" AND EventID == "7045") AND ((ServiceName="PAExec-*") OR (ImagePath="C:\\WINDOWS\\PAExec-*")))
