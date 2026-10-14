# Checked proxy pool

Optional, disabled by default. Uses public HTTP CONNECT proxies supplied by the operator. Download/export candidates from Geonode and place numeric IP:port endpoints in a text file; this version does not scrape websites or automatically refresh their lists. No own node servers are used.

## Server configuration

Create `/opt/ip-roller/data/proxies.txt`, one endpoint per line, without credentials. Both `IP:port` and `http://IP:port` are accepted. Private, loopback, non-numeric and unsupported protocol endpoints are discarded. The file is reloaded on selection; maximum 100 candidates. It resides in ignored data/.

In `/opt/ip-roller/.env`:

```dotenv
PROXY_POOL_ENABLED=true
PROXY_POOL_PATH=/opt/ip-roller/data/proxies.txt
PROXY_FAILURE_THRESHOLD=3
```

Ensure the iproller service user can read the file. Restart ip-roller, then start desired accounts in the dashboard. No new Python packages are needed.

## Behaviour

Each candidate must pass two credential-free HTTPS checks of IAM and all selected regions, with verified TLS and eight-second request timeouts. IAM must return 401 with a Keystone authentication header. Regional roots must return an accepted HTTP status. This verifies current connectivity, not IP reputation, ownership, future uptime or successful authenticated access.

Each active account receives a separate proxy endpoint. Different endpoints are not guaranteed to have different exit IPs. Direct fallback is disabled. Rejected endpoints are quarantined for 15 minutes; the pool is checked again after 60 seconds when none is available. HTTP proxies only; SOCKS requires additional implementation.

After three consecutive network failures in account API traffic, the proxy is quarantined. Subsequent traffic waits for a validated replacement, then resumes subject to existing account/zone cooldowns. This is an automatic pause of API traffic, not removal of the account or loss of its desired-running intent. HTTP responses reset the network-failure counter; 429, 401 and 403 do not rotate proxies. Reconciler and cleanup requests use the same account transport.

Failed requests are never automatically replayed by the proxy layer. Existing uncertain-create tracking and shared cost/resource/request limits remain active. A timed-out deletion still requires reconciliation. Manual Stop cancels selection after the existing graceful-stop timeout; emergency Stop remains available.

No live proxy, credential or Selectel tests were performed during development. Local mocked checks cover candidate filtering, failure threshold, reacquisition, non-replayed POST, handling 429 and lease cleanup. Validate on one account before starting the others.
