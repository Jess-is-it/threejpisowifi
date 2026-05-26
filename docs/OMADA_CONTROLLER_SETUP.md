# Omada Controller Setup

Omada Controller remains active in 3JCentralPisowifi. It is used for TP-Link Omada AP adoption, site/AP inventory, SSID configuration, and captive portal redirect/enforcement.

## Servers

```text
Omada Controller:       192.168.50.71
3JCentralPisowifi API:  192.168.50.70
Portal URL staging:     http://192.168.50.70:8080/portal
Portal URL production:  http://192.168.50.70/portal
```

## What Omada Does

- Adopts and manages Omada APs.
- Manages sites, APs, radios, SSIDs, and SSID VLAN tagging.
- Hosts the open SSID captive portal policy.
- Redirects unauthenticated clients to the 3JCentralPisowifi portal.
- Authorizes clients after voucher validation when the Omada API path is supported.

## What Omada Does Not Do

- It does not store vouchers.
- It does not store customer wallets.
- It does not decide voucher validity.
- It does not replace PostgreSQL as the source of truth.

3JCentralPisowifi remains the source of truth for vouchers, wallets, portal sessions, authorization logs, and access decisions.

## Install From Admin Portal

Open:

```text
http://192.168.50.70:8080/admin/settings/omada-controller
```

This old Omada install/manage automation must remain available. It supports:

- Saving controller host/ports.
- Testing HTTP/HTTPS reachability.
- Saving SSH credentials.
- Testing SSH.
- Installing Omada Software Controller on the separate controller server.
- Starting, stopping, restarting, backing up, and viewing install logs.

The backend exposes only controlled Omada install/manage actions. It does not expose arbitrary shell command execution.

## Required Ports

- `8088/tcp`: HTTP controller UI
- `8043/tcp`: HTTPS controller UI
- `8843/tcp`: HTTPS portal when used by Omada
- `29810/udp`: discovery
- `29811/tcp`: management/adoption
- `29812/tcp`: adoption
- `29813/tcp`: upgrade
- `29814/tcp`: current management/adoption
- `29815/tcp`: controller/device management on newer Omada versions
- `29816/tcp`: controller/device management on newer Omada versions
- `29817/tcp`: controller/device management on newer Omada versions, if the controller listens on it

When APs are on a routed AP management VLAN behind MikroTik, Network -> MikroTik -> AP Management Push Config adds managed forward allow rules from the AP management subnet to the controller for `29810/udp` and `29811-29817/tcp`. These rules must be before any generic forward drop that blocks AP management traffic from reaching `192.168.50.71`.

Office AP Path is retired from the active Network UI. For now, adopt factory-reset APs by connecting them directly to the office subnet, then set the AP management VLAN after successful adoption before moving the AP to the field path.

If Omada Controller is reinstalled, local Sites Deployments records may point to old Omada site IDs. Use APs Deployment -> Sites -> Sync Omada Sites to recreate missing local sites in Omada or relink by matching site name. The local Sites table remains the planning source of truth for addresses, map coordinates, and station bindings.

## Active Captive Portal Workflow

1. Configure the open SSID in APs Deployment -> Sites -> Configurations.
2. Bind the station to the correct Omada site from Network -> MikroTik -> Configuration.
3. Ensure the SSID VLAN matches the station customer VLAN.
4. Configure Omada Portal Authentication / External Portal.
5. Set the external portal URL to `http://192.168.50.70:8080/portal` for staging.
6. Allow pre-auth/walled-garden access to `192.168.50.70` and DNS as required by the controller.
7. Test on one AP before wider rollout.

## Retired Items

RADIUS profile automation, WPA2-Enterprise test SSID automation, NAS/RADIUS client setup, and FreeRADIUS packet tests are removed from the active system. Historical database tables may remain, but the UI/API should not expose those workflows.

## Troubleshooting

Omada API login failed:
- Confirm controller host, port, username, and password.
- For lab/self-signed certificates, disable TLS verification in Omada API settings.

AP not visible:
- Confirm the AP management subnet can reach `192.168.50.71`.
- Confirm DHCP option 138 or Omada inform/discovery is configured if the AP is outside the controller subnet.
- Confirm firewall/raw rules do not block controller/AP traffic.

Voucher valid but authorization failed:
- Check Captive Portal -> Authorization Logs.
- Confirm Omada is sending client context such as client MAC/token/site.
- If API authorization is unsupported by this controller version, use the manual Omada portal setup flow.

Client authorized but no internet:
- Confirm the SSID VLAN matches the station customer VLAN.
- Confirm MikroTik station transport has DHCP/NAT/routing pushed.
- Confirm Omada portal policy allows internet after authorization.
