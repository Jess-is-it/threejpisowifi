# Public HTTPS With Cloudflare Tunnel

3JCentralPisowifi uses Cloudflare Tunnel as the preferred production public HTTPS endpoint.

## Purpose

The tunnel gives the captive portal and payment webhooks a stable public HTTPS URL without opening inbound MikroTik ports.

Recommended hostname:

```text
https://net.3jhotspot.com/portal
```

## Current Design

- Cloudflare DNS owns `3jhotspot.com`.
- Cloudflare Tunnel connector runs from the 3JCentralPisowifi API container.
- The connector reaches the local Docker reverse proxy at `http://proxy:80`.
- Cloudflare terminates public HTTPS.
- MikroTik routers do not need public port-forward rules for the portal.

## Setup Page

Open:

```text
System Settings -> Public HTTPS
```

The page lets the operator:

- Save the domain and public hostname.
- Paste the Cloudflare connector command or raw tunnel token.
- Store the tunnel token encrypted.
- Start, stop, or restart the local `cloudflared` connector.
- Check local service health and public HTTPS health.
- View recent connector logs.

## Cloudflare Public Hostname

In Cloudflare One, configure the tunnel public hostname as:

```text
Subdomain: net
Domain: 3jhotspot.com
Type: HTTP
URL: http://proxy:80
```

The `http://proxy:80` value is intentional because `cloudflared` runs inside the same Docker network as the app reverse proxy.

## Security

- The tunnel token is sensitive and is stored encrypted.
- The token is written to a local token file and passed to `cloudflared` with `--token-file`.
- Do not commit tunnel tokens to Git.
- Keep admin access protected. Public access should focus on `/portal` and payment webhook routes.

## Payment Webhooks

PayMongo webhook endpoints should use the public HTTPS hostname:

```text
https://net.3jhotspot.com/api/payments/paymongo/webhook
```

Webhook signing secrets are still configured in:

```text
System Settings -> Payments
```

## Omada Captive Portal

Omada external portal URL should use:

```text
https://net.3jhotspot.com/portal
```

Unauthenticated clients must be allowed to reach the portal hostname and any required PayMongo/GCash checkout domains through Omada pre-auth/walled-garden rules.
