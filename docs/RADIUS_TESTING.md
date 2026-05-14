# RADIUS Testing

## Admin Portal Test Types

Simulated backend decision test:
- Runs inside the API only.
- Does not send a UDP RADIUS packet.
- Validates source-of-truth rules for user status, password, wallet balance, valid-until, unlimited flag, and active session conflict.

Internal real FreeRADIUS packet test:
- Sends a real UDP Access-Request from the API container to the FreeRADIUS container.
- Uses the fixed internal client `Docker API Test NAS`.
- IP/Subnet: `172.18.0.0/16`.
- Shared secret: the same `RADIUS_DEFAULT_SECRET` used by the FreeRADIUS Docker client.
- This does not use router/AP NAS shared secrets because the packet is not sent from the router/AP.

Internal real RADIUS accounting test:
- Sends real UDP Accounting-Request packets from the API container to the FreeRADIUS container.
- Host: `radius`.
- Accounting port: `1813` inside Docker.
- Uses the internal Docker test client secret, not a router/AP NAS shared secret.
- Supports Accounting Start, Interim-Update, and Stop.
- Start creates an ACTIVE session.
- Interim-Update deducts wallet time based on elapsed session time.
- Stop closes the session and performs final deduction.

External NAS/router/AP test:
- Use this for MikroTik, Omada, hostapd, or `radtest` from another machine.
- The external device must be added in NAS / Router / AP Clients.
- Use the shared secret from that NAS/router/AP record.

Production ports:
- Authentication: `1812/udp`
- Accounting: `1813/udp`

Staging ports:
- Authentication: `11812/udp`
- Accounting: `11813/udp`

Production radtest:

```bash
radtest testuser testpassword SERVER-IP:1812 0 SHARED_SECRET
```

Staging radtest:

```bash
radtest testuser testpassword SERVER-IP:11812 0 SHARED_SECRET
```

Expected Access-Accept:
- User exists.
- Password is correct.
- User is active.
- User has time remaining, a future valid-until date, or unlimited enabled.
- User has no active session inside the active session grace window.

Expected Access-Reject:
- Unknown user.
- Wrong password.
- Disabled user.
- No balance or expired access.
- Same account already has an active session.

The Admin Portal should display the FreeRADIUS `Reply-Message` as the diagnostic reason. Expected reject reasons include:
- `Unknown user`
- `Invalid password`
- `User disabled`
- `No active wallet balance`
- `Account expired`
- `Active session already exists`
- `Database lookup failed`
- `Unknown authorization failure`

Accounting can be tested with RADIUS client tools that send Start, Interim-Update, and Stop packets. The Admin Portal Sessions page should show the session and last seen time.

## Accounting radclient examples

Staging external accounting target:

```bash
127.0.0.1:11813 acct SHARED_SECRET
```

Accounting Start:

```bash
cat <<'EOF' | radclient -x 127.0.0.1:11813 acct SHARED_SECRET
User-Name = testuser
Acct-Status-Type = Start
Acct-Session-Id = test-session-001
NAS-IP-Address = 192.168.50.70
NAS-Identifier = staging-test
Calling-Station-Id = AA-BB-CC-DD-EE-FF
Framed-IP-Address = 10.10.10.10
EOF
```

Accounting Interim-Update:

```bash
cat <<'EOF' | radclient -x 127.0.0.1:11813 acct SHARED_SECRET
User-Name = testuser
Acct-Status-Type = Interim-Update
Acct-Session-Id = test-session-001
NAS-IP-Address = 192.168.50.70
NAS-Identifier = staging-test
Calling-Station-Id = AA-BB-CC-DD-EE-FF
Framed-IP-Address = 10.10.10.10
Acct-Session-Time = 300
Acct-Input-Octets = 100000
Acct-Output-Octets = 200000
EOF
```

Accounting Stop:

```bash
cat <<'EOF' | radclient -x 127.0.0.1:11813 acct SHARED_SECRET
User-Name = testuser
Acct-Status-Type = Stop
Acct-Session-Id = test-session-001
NAS-IP-Address = 192.168.50.70
NAS-Identifier = staging-test
Calling-Station-Id = AA-BB-CC-DD-EE-FF
Framed-IP-Address = 10.10.10.10
Acct-Session-Time = 600
Acct-Input-Octets = 250000
Acct-Output-Octets = 500000
EOF
```

## Phase 1C acceptance workflow

1. Add 1 hour balance to a user.
2. Run Real FreeRADIUS Packet Test and confirm `Access-Accept`.
3. Send Accounting Start and confirm the Sessions page shows ACTIVE.
4. Run Real FreeRADIUS Packet Test again and confirm `Access-Reject: Active session already exists`.
5. Send Interim-Update with `Acct-Session-Time = 300` and confirm wallet time decreases.
6. Send Accounting Stop and confirm the session becomes STOPPED.
7. Run Real FreeRADIUS Packet Test again and confirm `Access-Accept` if balance remains.

MikroTik guidance:
- Set RADIUS server to the Ubuntu server IP.
- Use the production or staging auth/accounting ports.
- Use the shared secret from the NAS / Router / AP Client record.
- Enable PPP, Hotspot, or wireless authentication depending on your test setup.

Omada standalone AP guidance:
- Configure external RADIUS server IP as the Ubuntu server IP.
- Use the environment-specific auth/accounting ports.
- Use the shared secret from the Admin Portal.

## Omada AP Real Device Test

Use the Omada Controller setup page:

```text
http://192.168.50.70:8080/admin/settings/omada-controller
```

Staging RADIUS values:
- Server: `192.168.50.70`
- Authentication port: `11812`
- Accounting port: `11813`

Production RADIUS values:
- Server: `192.168.50.70`
- Authentication port: `1812`
- Accounting port: `1813`

Before testing, create a NAS / Router / AP Client for the IP FreeRADIUS sees as the RADIUS source. This may be `192.168.50.71` for the Omada Controller or the AP IP.

Real AP checklist:
1. Install and open Omada Controller.
2. Adopt one Omada AP.
3. Create SSID `3J-Test-WiFi`.
4. Set security to WPA2-Enterprise.
5. Add RADIUS server `192.168.50.70`.
6. Use auth port `11812` and accounting port `11813` for staging.
7. Use the NAS client shared secret.
8. Create a test user and add wallet balance.
9. Connect a phone/laptop.
10. Confirm Access-Accept, Accounting Start, Interim-Update wallet deduction, and same-account second-device rejection.

Check FreeRADIUS logs:

```bash
docker logs centralwifi_staging-radius-1
```

hostapd guidance:
- Set `auth_server_addr`, `auth_server_port`, and `auth_server_shared_secret`.
- Set `acct_server_addr`, `acct_server_port`, and `acct_server_shared_secret`.

## Phase 1E Omada RADIUS Profile Automation Test

Use staging first:

```text
RADIUS Server: 192.168.50.70
Auth Port: 11812
Accounting Port: 11813
Interim Update: 300 seconds
SSID: 3J-Test-WiFi
Security: WPA2-Enterprise
```

Expected real AP behavior:
1. Omada API login succeeds.
2. Omada site is selected.
3. Matching NAS client exists in 3JCentralPisowifi using the same shared secret.
4. Omada RADIUS profile exists or is manually created from fallback values.
5. Test WPA2-Enterprise SSID exists or is manually created.
6. Phone/laptop connects with a 3JCentralPisowifi test user.
7. FreeRADIUS logs show Access-Accept.
8. Accounting Start creates an active session.
9. Interim-Update deducts wallet time.
10. A second device using the same account is rejected.

Check logs:

```bash
docker logs centralwifi_staging-radius-1
```

If FreeRADIUS reports an unknown client, create another NAS client for the source IP shown in the log using the same shared secret.

## Captive Portal Direction

RADIUS and WPA2-Enterprise tests are now advanced/lab tools, not the primary customer login flow.

Current customer direction:
- Customer connects to open SSID `3J-FreeWiFi`.
- Captive Portal opens at `http://192.168.50.70/portal`.
- Customer enters a voucher code.
- 3JCentralPisowifi validates the voucher and grants time/access.
- Session and accounting foundations remain useful for tracking and enforcement.

Keep these RADIUS tests available for backend validation. Do not remove Phase 1C authentication, accounting, wallet deduction, session tracking, or single-device rejection tests.
