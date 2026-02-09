/*
  Objective:
  Link suspicious authentication behavior to subsequent Pix transactions.

  Logic (simplified and portfolio-friendly):
  1) Find user+device pairs with >= 5 failed LOGIN/OTP attempts in the last 24 hours.
  2) For those users, search for APPROVED Pix transactions in the last 24 hours
     that happened within 20 minutes after the last failed attempt.
  3) Require at least one "suspicious Pix" condition:
     - new recipient in last 7 days OR new device in last 30 days OR high amount (>= 500).
*/

WITH auth_suspects AS (
  SELECT
    user_id,
    device_id,
    COUNT(*) AS auth_fail_count_24h,
    MIN(event_ts) AS first_fail_ts_24h,
    MAX(event_ts) AS last_fail_ts_24h,
    COUNT(DISTINCT ip_address) AS distinct_ip_count_24h
  FROM auth_events
  WHERE event_result = 'FAIL'
    AND event_type IN ('LOGIN', 'OTP')
    AND event_ts >= current_timestamp() - INTERVAL 24 HOURS
  GROUP BY user_id, device_id
  HAVING COUNT(*) >= 5
),

pix_after_fail_agg AS (
  SELECT
    a.user_id,

    COUNT(*) AS pix_approved_count_20m,
    SUM(pt.amount) AS pix_total_amount_20m,
    MAX(pt.amount) AS pix_max_amount_20m,

    SUM(CASE WHEN pt.is_new_recipient_7d = 1 THEN 1 ELSE 0 END) AS pix_new_recipient_cnt_20m,
    SUM(CASE WHEN pt.is_new_device_30d = 1 THEN 1 ELSE 0 END) AS pix_new_device_cnt_20m,

    COUNT(DISTINCT pt.recipient_key_hash) AS distinct_recipients_20m,

    MAX(
      CASE
        WHEN pt.is_new_recipient_7d = 1
          OR pt.is_new_device_30d = 1
          OR pt.amount >= 500
        THEN 1 ELSE 0
      END
    ) AS has_suspicious_pix_20m

  FROM auth_suspects a
  INNER JOIN pix_transactions pt
    ON pt.user_id = a.user_id
   AND pt.status = 'APPROVED'
   AND pt.tx_ts >= current_timestamp() - INTERVAL 24 HOURS
   AND pt.tx_ts >= a.last_fail_ts_24h
   AND pt.tx_ts <= a.last_fail_ts_24h + INTERVAL 20 MINUTES

  GROUP BY a.user_id
  HAVING MAX(
    CASE
      WHEN pt.is_new_recipient_7d = 1
        OR pt.is_new_device_30d = 1
        OR pt.amount >= 500
      THEN 1 ELSE 0
    END
  ) = 1
)

SELECT *
FROM pix_after_fail_agg
ORDER BY pix_total_amount_20m DESC, pix_approved_count_20m DESC;
