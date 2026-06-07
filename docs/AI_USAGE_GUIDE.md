# AI Usage Guide

AI features are no longer part of the active 3JCentralPisowifi operator workflow.

## Current Rule

- Do not add AI chat, AI explain, AI smoke tests, AI planning suggestions, or AI draft deployment plans unless the project owner explicitly reopens the feature.
- Do not expose OpenAI settings in the admin UI.
- Do not call OpenAI from the MikroTik preflight or captive portal workflow.
- Keep MikroTik setup manual and deterministic under `Admin -> Network -> MikroTik -> Configuration`.
- Keep MikroTik read-only preflight scan data because it provides validation input for manual operator fields such as VLAN IDs, subnets, pools, DHCP, legacy HotSpot objects, PPPoE, OSPF, WireGuard, routing, and firewall risk indicators. The scan UI now lives inside `Admin -> Network -> MikroTik -> Configuration`.

## Safety Boundary

- Preflight scanning remains read-only.
- Manual MikroTik configuration must show exact RouterOS changes before any step is applied.
- Backend deterministic validation remains the authority for VLAN conflicts, subnet overlaps, pool overlaps, missing required fields, and protected-router warnings.
- No AI output should be used to approve, generate, or apply RouterOS configuration.

## General Project Rules

- Always update `/PROJECT_CONTEXT.md` whenever architecture, deployment, features, commands, branches, workflows, or decisions change.
- Preserve the production/staging deployment model.
- Keep secrets in environment-specific `.env` files and never commit generated secrets.
- Current product priority is Captive Portal + WiFi Pass access.
- Omada is the captive portal enforcement layer; MikroTik remains for station VLAN/DHCP/NAT/AP-management transport.
- Preserve vouchers for events/refunds/gifts, portal, Product Items, Physical Stores, customer WiFi Bag, Omada Controller install/manage automation, Omada AP/SSID workflows, and MikroTik read-only scan/station transport features.
- RADIUS/authentication/accounting/session lab tools, OpenAI settings, AI assistant, and MikroTik HotSpot enforcement are retired from the active product workflow.
- Wallet / Manual Top-Up is removed completely and must not be rebuilt unless the project owner explicitly changes direction.
