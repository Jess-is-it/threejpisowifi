# 3JCentralPisowifi

Phase 1: Source of Truth + Manual RADIUS Test MVP.

3JCentralPisowifi provides a Dockerized Admin Portal, FastAPI backend, PostgreSQL source-of-truth database, Redis, and FreeRADIUS for manual user, wallet, NAS/router/AP, RADIUS authentication, and accounting tests.

## Branch Strategy

- `master` = Production
- `staging` = Staging

Develop and test on `staging`. Merge to `master` only after staging is verified.

## One-Line Install

Production:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/master/deploy/install.sh | sudo bash -s -- install production
```

Staging:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/staging/deploy/install.sh | sudo bash -s -- install staging
```

## One-Line Update

Production:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/master/deploy/install.sh | sudo bash -s -- update production
```

Staging:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/staging/deploy/install.sh | sudo bash -s -- update staging
```

## Local Commands

```bash
sudo ./deploy/install.sh install production
sudo ./deploy/install.sh install staging
sudo ./deploy/install.sh update production
sudo ./deploy/install.sh update staging
```

## Admin Portal

- Production: `http://SERVER-IP/admin`
- Staging: `http://SERVER-IP:8080/admin`

Phase 1 is for manual RADIUS testing only. Read [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) before changing this project.
