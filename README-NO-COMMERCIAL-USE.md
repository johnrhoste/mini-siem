# mini-siem

** IMPORTANT **

This project is NOT INTENDED FOR COMMERCIAL, ENTERPRISE, AND/OR PRODUCTION ENVIRONEMNTS.

This was created as a basic, very lightweight SIEM, focusing on 4 main uses:

1. Log collection
2. Log Parsing & Normalization
3. Correlation & Detection - looking for suspicious patterns.
4. Alerting

In this multi-threaded Python Script, one thread continuously watches a log file (using "tail"), while the main thread parses through logs, checks them against rules, and triggers alerts.

The log is monitoring auth.log, an authentication log, and watching for brute force attacks -- defined as more than 3 failed login attempts from the same IP address in a short amount of time.

OPTIONAL ADDITIONS:

• Real-time alerting / Webhooks - the "requests" library can send POST requests to a Slack, Discord, or other webhook to enable live notifications.

• Historical searching - Python's built-in "sqlite3" module can log all events into a database for later searching.

• GeoIP - use a library like "geoip2" to look up public IP addresses to determine if traffic is coming from unexpected regions.
