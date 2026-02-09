/*
  Objective:
  Produce an investigation queue with a simple priority score and rank per user.

  Inputs:
  - auth_suspects: suspicious auth behavior per user+device
  - pix_after_fail_agg: Pix behavior after last failure (within 20 minutes)
  - user_profile: customer context (segment, account age, historical risk score)
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
    COUNT(DISTINCT pt.recipient_key_hash) AS distinct_recipients_20m
  FROM auth_suspects a
  INNER JOIN pix_transactions pt
    ON pt.user_id = a.user_id
   AND pt.status = 'APPROVED'
   AND pt.tx_ts >= current_timestamp() - INTERVAL 24 HOURS
   AND pt.tx_ts >= a.last_fail_ts_24h
   AND pt.tx_ts <= a.last_fail_ts_24h + INTERVAL 20 MINUTES
  GROUP BY a.user_id
),

final_queue AS (
  SELECT
    a.user_id,
    a.device_id,

    a.auth_fail_count_24h,
    a.first_fail_ts_24h,
    a.last_fail_ts_24h,
    a.distinct_ip_count_24h,

    p.pix_approved_count_20m,
    p.pix_total_amount_20m,
    p.pix_max_amount_20m,
    p.pix_new_recipient_cnt_20m,
    p.pix_new_device_cnt_20m,
    p.distinct_recipients_20m,

    up.segment,
    up.account_age_days,
    up.risk_score,
    up.home_state,

    (
      (a.auth_fail_count_24h * 1)
      + (p.pix_approved_count_20m * 2)
      + (p.pix_new_recipient_cnt_20m * 3)
      + (p.pix_new_device_cnt_20m * 3)
      + (up.risk_score / 10)
      + (CASE WHEN a.distinct_ip_count_24h >= 3 THEN 5 ELSE 0 END)
      + (CASE WHEN p.pix_max_amount_20m >= 500 THEN 5 ELSE 0 END)
    ) AS priority_score

  FROM auth_suspects a
  INNER JOIN pix_after_fail_agg p
    ON a.user_id = p.user_id
  LEFT JOIN user_profile up
    ON a.user_id = up.user_id
),

ranked_queue AS (
  SELECT
    fq.*,
    ROW_NUMBER() OVER (
      PARTITION BY fq.user_id
      ORDER BY
        fq.priority_score DESC,
        fq.auth_fail_count_24h DESC,
        fq.last_fail_ts_24h DESC
    ) AS device_rank_per_user
  FROM final_queue fq
)

SELECT *
FROM ranked_queue
ORDER BY priority_score DESC;
