// Title: Azure DNS Zone Modified or Deleted
// ID: af6925b0-8826-47f1-9324-337507a0babd
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-08
// Tags: attack.impact, attack.t1565.001
// Description: Identifies when DNS zone is modified or deleted.
// Converted by: Sigma Universal SIEM/EDR CLI

(operationName="MICROSOFT.NETWORK/DNSZONES*" AND (operationName="*/WRITE" OR operationName="*/DELETE"))
