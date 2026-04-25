# Install

Production install:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/master/deploy/install.sh | sudo bash -s -- install production
```

Staging install:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/staging/deploy/install.sh | sudo bash -s -- install staging
```

Local production install:

```bash
sudo ./deploy/install.sh install production
```

Local staging install:

```bash
sudo ./deploy/install.sh install staging
```

The installer checks Ubuntu 22.04+, installs Docker and Docker Compose if missing, creates an environment-specific `.env`, asks for the first admin account, starts services, runs migrations, seeds the admin, and opens only the required firewall ports without blocking SSH.
