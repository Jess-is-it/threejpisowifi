# Top-Up Portal

The Central WiFi Top-Up Portal is the end-user page served at:

- `http(s)://<your-domain-or-ip>/portal`

It supports:

- Requesting WiFi credentials via SMS (mock by default)
- Checking wallet status
- Buying plans (mock payment by default)

## Important: WPA2-Enterprise and “show portal when no credit”

With WPA2-Enterprise (802.1X), if a user has **no active plan**, RADIUS normally **rejects** authentication.
In a pure reject flow, the device never gets network access, so there is no way to “auto-show a web portal”.

To get a portal experience, use one of these approaches:

### Option A (Recommended): Separate “TopUp SSID” with captive portal

1. Create a separate SSID in Omada, for example:
   - SSID: `CentralWiFi-TopUp`
   - Security: Open or WPA2-PSK (your preference)
2. Enable Omada Portal for that SSID and set the portal URL to:
   - `http(s)://<server>/portal`
3. In your Omada walled garden settings, allow access to:
   - `<server>` (the same host you configured above)

Flow:
- User connects to `CentralWiFi-TopUp` -> portal opens -> user buys -> user connects to WPA2-Enterprise SSID.

### Option B (Advanced): RADIUS VLAN “Walled Garden” when no credit

If your AP/controller supports VLAN assignment via RADIUS attributes, you can enable:

- `WALLED_GARDEN_ON_NO_CREDIT=1`
- `WALLED_GARDEN_VLAN_ID=<your_vlan_id>`

This causes RADIUS to:
- `ALLOW` users with credit normally
- For users with **no** credit: `ACCEPT` them but assign a VLAN (restricted network)

You must then configure your network/firewall so that this VLAN can only reach:
- the portal (`/portal`)
- the API endpoints required by the portal (`/api/v1/portal/*`)
- optional payment endpoints

Note: VLAN enforcement is done by your network/AP/controller, not by this server.

