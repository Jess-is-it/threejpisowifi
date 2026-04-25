3JCentralPisowifi

Short description:
Phase 1 Source of Truth + Manual RADIUS Test MVP for admin-managed WiFi user, manual balance, NAS/router/AP client, RADIUS authentication, and accounting tests.

GitHub branch strategy:
- master = Production
- staging = Staging
- Developers work on staging.
- Test deployment uses staging.
- Merge staging into master only after testing.
- Production updates from master.

Repository URL placeholder:
https://github.com/YOUR_ORG/3jcentralpisowifi

One-line production install:
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/master/deploy/install.sh | sudo bash -s -- install production

One-line staging install:
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/staging/deploy/install.sh | sudo bash -s -- install staging

One-line production update:
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/master/deploy/install.sh | sudo bash -s -- update production

One-line staging update:
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/3jcentralpisowifi/staging/deploy/install.sh | sudo bash -s -- update staging

Local production install:
sudo ./deploy/install.sh install production

Local staging install:
sudo ./deploy/install.sh install staging

Local production update:
sudo ./deploy/install.sh update production

Local staging update:
sudo ./deploy/install.sh update staging

Admin portal URL format:
- Production: http://SERVER-IP/admin
- Staging: http://SERVER-IP:8080/admin

Warning:
Phase 1 is for manual RADIUS testing only. Do not treat it as a complete captive portal or payment-enabled production flow.

Reference:
Read PROJECT_CONTEXT.md first before changing this project.
