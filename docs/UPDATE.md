# Update

Production update:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/master/deploy/install.sh | sudo bash -s -- update production
```

Staging update:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/staging/deploy/install.sh | sudo bash -s -- update staging
```

Local update commands:

```bash
sudo ./deploy/install.sh update production
sudo ./deploy/install.sh update staging
```

The updater backs up the target environment, pulls the correct branch, runs migrations, restarts only the target Compose project, and runs health checks. If health checks fail, use `deploy/restore.sh` with the printed backup directory.
