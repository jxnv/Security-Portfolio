// Title: Azure Service Principal Created
// ID: 0ddcff6d-d262-40b0-804b-80eb592de8e3
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-09-02
// Tags: attack.stealth
// Description: Identifies when a service principal is created in Azure.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (operationName = "Add service principal")
