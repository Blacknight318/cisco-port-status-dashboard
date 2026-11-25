# Cisco Port Status Dashboard — v0.5

A local, read-only web dashboard for a single Cisco switch. It collects interface status over SSH and maps ports as follows:

- **Green:** `connected`
- **Yellow:** `notconnect` (enabled but no physical link)
- **Gray:** `disabled` (administratively disabled)
- **Red:** `err-disabled`
- **Blue:** any unrecognized state

## Security model

- The service binds only to `127.0.0.1`.
- Passwords are request-only: they are not saved to disk, browser storage, logs, or exports. The page clears them after each request.
- A secondary credential is tried only after the primary credential receives an SSH authentication failure.
- The application accepts only the fixed operational commands in `app.py`; it has no configuration/apply capability.
- The first SSH connection requires you to verify and explicitly accept the switch host-key fingerprint. Confirm it from a trusted console or inventory source before accepting. Accepted public host keys are stored in the local `known_hosts` file; passwords are never stored.

## Requirements

- Python 3.11 or newer
- Network reachability from the machine running the dashboard to the Cisco switch on TCP/22
- A Cisco account allowed to run `show interfaces status`, `show interfaces description`, `show mac address-table`, and `show logging | include %LINK-|%LINEPROTO-`

## Install and run

Run on the Linux host that can reach the switch. The included startup script creates its own environment, prefers `uv` when available, and binds only to loopback:

```bash
cd cisco-port-status-dashboard
chmod +x run.sh
./run.sh
```

Open `http://127.0.0.1:8787` in a browser on that host.

To install manually instead, create a Python virtual environment, install `requirements.txt`, and run:

```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8787
```

For a remote workstation, create an encrypted SSH forward to the dashboard host:

```bash
ssh -N -L 8787:127.0.0.1:8787 your-user@dashboard-host
```

Then open `http://127.0.0.1:8787` locally.

## Test the parser

```bash
. .venv/bin/activate
python -m unittest discover -s tests -v
```

## Current scope and limits

- Each port displays its `show interfaces description` description when present; the shorter status-table name is only used when a description is absent.
- Each port has a collapsed **MAC addresses (N)** section. Expanding it shows each learned MAC with its VLAN and dynamic/static table type. CPU/router entries are not assigned to physical port cards.
- Each port has a collapsed **Link events in switch log (N)** section. It maps `%LINK` and `%LINEPROTO` up/down transitions from the currently retained switch log buffer; amber text means matching events were found. This is evidence of link-state transitions, not a persisted or timed flapping alert.
- The SSH transport supports older IOS devices that require `diffie-hellman-group14-sha1`, while retaining stronger algorithms as preferred and refusing obsolete `diffie-hellman-group1-sha1`.
- Collection uses one interactive SSH shell because some older IOS releases close Paramiko `exec_command()` channels.
- Supports one switch at a time.
- Expects conventional IOS/IOS-XE `show interfaces status` column formatting. Different models/releases may need a parser adjustment; save sanitized command output before making that change.
- It deliberately has no automatic refresh or saved switch inventory in this first package.
- It does not accept an enable secret and does not run any configuration commands.
