# Security Log Analyzer

A rule-based log analyzer written in Python and Pandas. It reads login and server logs, applies five detection rules, and produces a severity-graded alert report (HIGH / MEDIUM / LOW) with a summary chart.

## Problem

Reviewing security logs by hand to spot attacks is slow and error-prone. This project automates the detection of common suspicious patterns with simple, explainable rules.

## Data

The project uses **synthetically generated logs** (no real user data). The notebook creates:

- 300 normal login events over about 7 days, from 5 internal IPs and 6 usernames (about 15% failures, to mimic ordinary mistyped passwords)
- 14 failed logins from one IP against `admin` within 28 minutes (brute-force pattern)
- 23 failed logins from one IP across 23 different usernames (account-enumeration pattern)
- 6 successful `/reports` accesses from one IP between 2 AM and 3 AM (off-hours pattern)

Total: 343 events. Each event has a timestamp, IP, username, status (success/fail) and endpoint. A fixed random seed (`42`) makes the results reproducible.

## Detection Rules

| # | Rule | Logic | Severity |
|---|---|---|---|
| 1 | Brute force | An IP with 10 or more failed logins **within a 30-minute window** | HIGH |
| 2 | Account targeting | A username with 5 or more failed logins | MEDIUM |
| 3 | IP scanning / enumeration | An IP that failed against 10 or more different usernames | MEDIUM |
| 4 | Unusual hours | Activity between 2 AM and 4 AM | LOW |
| 5 | Repeated restricted access | An IP hitting `/admin_panel` or `/user_data` 15 or more times | LOW |

### Improving Rule 1

The first version counted all failed logins per IP over the whole week. That flagged 5 IPs as HIGH, but 3 of them were normal IPs that had simply accumulated failures over several days. Adding a **30-minute sliding window** reduced the HIGH alerts to the 2 IPs that actually behave like attackers (`192.168.1.45` and `10.20.5.18`).

## Sample Output

- HIGH: 2 alerts (brute force)
- MEDIUM: 7 alerts (6 targeted accounts, 1 IP scanning)
- LOW: 8 alerts (6 unusual-hour IPs, 2 repeated restricted access)

## Tech Stack

Python, Pandas, Matplotlib, Jupyter / Google Colab

## How to Run

1. Clone this repository.
2. Open `security_log_analyzer.ipynb` in Google Colab or Jupyter.
3. Run all cells from top to bottom (Runtime > Run all). This generates the logs, runs the five rules, prints the alert report and draws the chart.

## Limitations

- The logs are synthetic, so the results show that the rules work on the injected patterns, not how they would perform on real traffic.
- Thresholds (10 failures, 30 minutes, 2-4 AM, 15 accesses) were chosen by hand, not tuned on real data.
- Rule 2 flags every account, because random failures in the normal traffic also cross the 5-failure threshold. Rule 4 flags several normal IPs. Both rules are too broad for real use.
- Rules work on a fixed batch of logs. There is no real-time processing.

## Future Work

- Add a time window to Rule 2, and a per-IP baseline to Rule 4, to reduce false alerts.
- Test on a public log dataset instead of generated data.
- Try an anomaly-detection model (for example Isolation Forest) and compare it with the rules.
- Export the alert report to CSV.
