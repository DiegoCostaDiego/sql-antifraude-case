# SQL Antifraud Case Study

## Context
This project simulates a real-world antifraud analysis scenario in the banking domain.
The goal is to identify suspicious authentication behavior that may indicate account takeover attempts.

## Problem
- Identify users with multiple failed authentication attempts
- Reduce false positives by analyzing behavior per user and device
- Provide a defensible analytical output for investigation prioritization

## Data Assumptions
The analysis assumes fictitious tables commonly found in banking environments:
- auth_events (authentication attempts)

All data is fictional and used only for analytical demonstration.

## Approach
- Time-based filtering (last 24 hours)
- Focus on failed LOGIN and OTP attempts
- Aggregation by user and device to isolate attack vectors
- Use of HAVING clause to filter suspicious behavior

## Key SQL Concepts
- WHERE vs HAVING
- COUNT aggregation
- Behavioral analysis per user/device

## Notes
This project focuses on analytical reasoning and clarity rather than performance optimization.

## Queries
- `queries/01_auth_failures.sql`: Finds user+device pairs with high failed LOGIN/OTP attempts (last 24h).
- `queries/02_pix_after_fail.sql`: Links suspicious auth behavior to APPROVED Pix within 20 minutes, requiring at least one suspicious Pix condition.
- `queries/03_ranked_queue.sql`: Produces an investigation queue with a simple priority score and ranks devices per user.
