# RADIUS Testing (radclient)

The stack exposes:

- 1812/udp: authentication
- 1813/udp: accounting

## 1) Create a user and credit wallet

Use the Admin UI:

- Create user `+15551234567`
- Credit 3600 seconds

## 2) Send an Access-Request (PAP)

From the server host:

```bash
echo \"User-Name = +15551234567\nUser-Password = <wifi-password>\nCalling-Station-Id = AA-BB-CC-DD-EE-FF\" | \\
  radclient -x 127.0.0.1:1812 auth \"$RADIUS_SHARED_SECRET\"
```

Expected: `Access-Accept`

## 3) Enforce single-device (different Calling-Station-Id)

```bash
echo \"User-Name = +15551234567\nUser-Password = <wifi-password>\nCalling-Station-Id = 11-22-33-44-55-66\" | \\
  radclient -x 127.0.0.1:1812 auth \"$RADIUS_SHARED_SECRET\"
```

Expected: `Access-Reject` with `Reply-Message` like `Already logged in on another device`.

## 4) Accounting Interim-Update (decrements TIME wallet)

```bash
echo \"User-Name = +15551234567\nAcct-Status-Type = Interim-Update\nCalling-Station-Id = AA-BB-CC-DD-EE-FF\nAcct-Session-Id = test-1\" | \\
  radclient -x 127.0.0.1:1813 acct \"$RADIUS_SHARED_SECRET\"
```

Re-run after ~60 seconds. The wallet `time_remaining_seconds` will decrease.

