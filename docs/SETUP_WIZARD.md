# Setup Wizard

The Admin UI includes a first-time **Setup Wizard** that guides operators through a safe, prioritized rollout:

- **Required**: network + firewall, RADIUS shared secret, NAS/AP client registration, test user + wallet credit
- **Recommended**: plans & pricing
- **Optional**: SMS provider, payment gateway, JuanFi vendo device registration

Access it from the Admin UI sidebar as **Setup Wizard** (route: `#/setup`).

The wizard stores its completion state in the database (`system_settings`) so you can:

- re-run the wizard in "edit mode" anytime
- reset the completion flag without deleting operational data (users/NAS/plans)

