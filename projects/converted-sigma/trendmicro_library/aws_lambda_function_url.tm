// Title: New AWS Lambda Function URL Configuration Created
// ID: ec541962-c05a-4420-b9ea-84de072d18f4
// Status: experimental
// Level: medium
// Author: Ivan Saakov
// Date: 2024-12-19
// Tags: attack.initial-access, attack.privilege-escalation
// Description: Detects when a user creates a Lambda function URL configuration, which could be used to expose the function to the internet and potentially allow unauthorized access to the function's IAM role for AWS API calls.
// This could give an adversary access to the privileges associated with the Lambda service role that is attached to that function.
// Converted by: Sigma Universal SIEM/EDR CLI

(eventSource: "lambda.amazonaws.com" AND eventName: "CreateFunctionUrlConfig")
