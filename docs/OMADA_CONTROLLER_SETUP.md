# Omada Controller Setup

Phase 1D prepares a real TP-Link Omada AP test while keeping 3JCentralPisowifi as the source of truth.

## Why Omada Is Separate

The Omada Software Controller should run on its own server:

```text
Omada server: 192.168.50.71
3JCentralPisowifi server: 192.168.50.70
```

This keeps AP management isolated from the RADIUS, wallet, session, and accounting system.

## What Omada Does

- Adopt Omada APs.
- Configure SSIDs.
- Configure WPA2-Enterprise / RADIUS profiles.
- Monitor AP status.

## What Omada Does Not Do

- It does not store WiFi customer accounts.
- It does not manage balances, vouchers, SMS, payments, or access decisions.
- It does not replace FreeRADIUS.

3JCentralPisowifi remains the source of truth. FreeRADIUS on `192.168.50.70` still handles authentication and accounting.

## Install From Admin Portal

Open:

```text
http://192.168.50.70:8080/admin/settings/omada-controller
```

Use the page to:
- Save controller host `192.168.50.71`.
- Test HTTP/HTTPS reachability.
- Save SSH credentials.
- Test SSH.
- Install Omada Software Controller on the separate server.
- View install logs.
- Open the Omada UI.

The backend only exposes controlled actions: detect, install, start, stop, restart, view logs, backup, and check ports. It does not allow arbitrary shell command execution.

## Required Ports

- `8088/tcp`: HTTP controller UI
- `8043/tcp`: HTTPS controller UI
- `8843/tcp`: HTTPS portal, parked for later
- `29810/udp`: discovery
- `29811/tcp`: management/adoption
- `29812/tcp`: adoption
- `29813/tcp`: upgrade
- `29814/tcp`: current management/adoption

## RADIUS Settings

Staging:

```text
RADIUS Server: 192.168.50.70
Authentication Port: 11812
Accounting Port: 11813
Accounting: Enabled
Interim Update: 300 seconds
```

Production:

```text
RADIUS Server: 192.168.50.70
Authentication Port: 1812
Accounting Port: 1813
Accounting: Enabled
Interim Update: 300 seconds
```

Use the shared secret from the matching NAS / Router / AP Client record.

## Adopt AP And Configure WPA2-Enterprise

1. Open Omada Controller UI.
2. Complete first-time setup.
3. Adopt one Omada AP.
4. Create SSID `3J-Test-WiFi`.
5. Set security to WPA2-Enterprise.
6. Add a RADIUS profile pointing to `192.168.50.70`.
7. Use staging auth port `11812` and accounting port `11813`.
8. Enable accounting if available.
9. Set interim update to 300 seconds if available.

## Correct NAS Source IP

Create a NAS / Router / AP Client entry for the IP that FreeRADIUS sees as the RADIUS packet source. Depending on Omada/AP behavior, this may be:

- Omada Controller IP: `192.168.50.71`
- AP management IP

If FreeRADIUS says unknown client or no reply appears in the UI, verify the source IP in FreeRADIUS logs and add that IP as the NAS client.

## Troubleshooting

Access-Reject:
- Check username and password.
- Check user status and wallet balance.
- Check active session conflict.
- Confirm the NAS shared secret matches Omada.

No Reply:
- Confirm Omada points to `192.168.50.70`.
- Confirm staging ports `11812/11813` or production ports `1812/1813`.
- Check firewall and UDP reachability.
- Check FreeRADIUS logs.

Accounting not showing:
- Enable accounting in Omada if available.
- Confirm accounting port is set.
- Confirm interim update is enabled.
- Confirm the source IP has a NAS client record.

## Phase 1E Omada API Automation

Open:

```text
http://192.168.50.70:8080/admin/settings/omada-controller
```

Use the API Automation tab to save:

```text
Controller Host: 192.168.50.71
HTTPS Port: 8043
API Base URL: https://192.168.50.71:8043
Verify TLS Certificate: disabled for lab/self-signed certificates
```

Omada credentials are used only to configure AP and SSID settings. Customer accounts, balances, sessions, and access decisions remain in 3JCentralPisowifi and FreeRADIUS.

Workflow:
1. Save Omada API settings.
2. Test API Login.
3. Refresh Sites and select the active site.
4. Build the staging RADIUS profile.
5. Create Matching RADIUS Trust Entry in 3JCentralPisowifi.
6. Attempt Create Omada RADIUS Profile.
7. Attempt Create Test WPA2-Enterprise SSID.
8. If automation fails, use the Manual Fallback Instructions panel.

Staging values:

```text
RADIUS Server: 192.168.50.70
Authentication Port: 11812
Accounting Port: 11813
Accounting: Enabled
Interim Update: 300 seconds
SSID: 3J-Test-WiFi
Security: WPA2-Enterprise
```

Production values:

```text
RADIUS Server: 192.168.50.70
Authentication Port: 1812
Accounting Port: 1813
Accounting: Enabled
Interim Update: 300 seconds
```

For Phase 1E, use staging first. Do not configure production WiFi until staging real-device testing passes.

Omada API endpoint paths vary across controller versions. The backend isolates endpoint guesses in the Omada API client adapter, saves sanitized automation logs, and shows manual fallback values instead of crashing if Omada rejects an endpoint.

If users cannot connect after the Omada profile is created, check the FreeRADIUS logs to identify the real NAS source IP. It may be the Omada Controller IP `192.168.50.71` or the AP management IP. Add that IP as a NAS client using the same shared secret.

## Captive Portal Priority

Omada remains useful for AP adoption, AP monitoring, and SSID management, but the main customer access direction is now Captive Portal + Voucher.

Planned captive portal values:

```text
Open SSID: from APs Deployment -> Sites -> Configurations -> SSID and Security
Portal URL: http://192.168.50.70/portal
Staging Admin: http://192.168.50.70:8080/admin
Portal Server: 3JCentralPisowifi
Voucher Source: 3JCentralPisowifi Database
Access Decision: Voucher + Wallet + Session rules
```

WPA2-Enterprise RADIUS profile and test SSID automation should be treated as advanced/lab tooling. Customers should not be asked for WPA2 identity, anonymous identity, or WiFi password in the main PisoWiFi-style experience.

## Phase 2C Captive Portal Integration

The main Omada customer setup is now:

```text
Open SSID: from APs Deployment -> Sites -> Configurations -> SSID and Security
Portal URL: http://192.168.50.70:8080/portal
Portal Server: 3JCentralPisowifi
Voucher Source: PostgreSQL voucher tables
Access Decision: 3JCentralPisowifi
```

Admin -> Captive Portal now includes:
- Portal Settings.
- Omada Integration actions.
- Test Flow checklist.
- Portal Sessions.
- Omada Authorization Logs.
- Manual Setup Guide.

Automation attempts to create the open SSID, configure an external portal profile, and authorize a client after voucher validation. Omada API endpoint behavior can vary by controller version, so the manual setup guide is always the fallback.

For one-AP testing, configure the Omada walled garden/pre-auth access to allow:
- `192.168.50.70`
- `http://192.168.50.70:8080/portal`
- DNS if your Omada version requires it before authentication
