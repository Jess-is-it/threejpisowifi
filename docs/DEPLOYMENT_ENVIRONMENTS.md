# Deployment Environments

Production:
- Branch: `master`
- Install path: `/opt/3jcentralpisowifi-production`
- `.env`: `/opt/3jcentralpisowifi-production/.env`
- Compose project: `centralwifi_prod`
- Database: `centralwifi_prod`
- Volumes: `centralwifi_prod_postgres_data`, `centralwifi_prod_redis_data`
- Web: `80/tcp`
- RADIUS auth/accounting: `1812/udp`, `1813/udp`

Staging:
- Branch: `staging`
- Install path: `/opt/3jcentralpisowifi-staging`
- `.env`: `/opt/3jcentralpisowifi-staging/.env`
- Compose project: `centralwifi_staging`
- Database: `centralwifi_staging`
- Volumes: `centralwifi_staging_postgres_data`, `centralwifi_staging_redis_data`
- Web: `8080/tcp`
- RADIUS auth/accounting: `11812/udp`, `11813/udp`

Production and staging can run on the same Ubuntu server because their project names, install paths, databases, volumes, and exposed ports are different.
