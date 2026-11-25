# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose switch access, host-key data, or credentials. Contact the repository owner privately with the affected version, reproduction steps, and impact.

## Deployment requirements

- Bind the dashboard only to `127.0.0.1`.
- Reach it remotely only through an authenticated SSH port forward or another approved encrypted access path.
- Use a dedicated least-privilege Cisco account restricted to the documented read-only `show` commands.
- Verify the displayed SSH host-key fingerprint before trusting a new switch.
- Never commit `known_hosts`, passwords, SSH keys, `.env` files, screenshots containing secrets, or production device inventories.

The application intentionally has no configuration-change or enable-secret workflow.
