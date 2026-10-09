// Title: Python SQL Exceptions
// ID: 19aefed0-ffd4-47dc-a7fc-f8b1425e84f9
// Status: stable
// Level: medium
// Author: Thomas Patzke
// Date: 2017-08-12
// Tags: attack.initial-access, attack.t1190
// Description: Generic rule for SQL exceptions in Python according to PEP 249
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ("DataError" or "IntegrityError" or "ProgrammingError" or "OperationalError")
