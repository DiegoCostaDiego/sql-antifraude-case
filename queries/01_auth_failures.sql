/*
  Objective:
  Identify users and devices with a high number of failed authentication attempts
  in the last 24 hours.

  Rationale:
  Multiple failed LOGIN or OTP attempts from the same device may indicate
  credential stuffing or account takeover attempts.
*/

SELECT
  user_id,
  device_id,
  COUNT(*) AS auth_fail_count_24h
FROM auth_events
WHERE event_result = 'FAIL'
  AND event_type IN ('LOGIN', 'OTP')
  AND event_ts >= current_timestamp() - INTERVAL 24 HOURS
GROUP BY
  user_id,
  device_id
HAVING COUNT(*) >= 5
ORDER BY auth_fail_count_24h DESC;
