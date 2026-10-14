# Easy Radius

Easy Radius is a small web page for managing FreeRADIUS 3.0 on Ubuntu 24.04. It keeps a list of MikroTik routers and users, writes `clients.conf` and the users file, checks the config, and restarts FreeRADIUS only when that check passes.

The page is meant to stay plain: log in, edit routers, edit users, apply, test a login.

The original logo is in [docs/easy-radius-logo.jpg](docs/easy-radius-logo.jpg). The site uses a matching inline SVG, not the JPEG.

A page-by-page walkthrough with screenshots is in [docs/USER_GUIDE.md](docs/USER_GUIDE.md).

## New server

Copy this directory onto the Ubuntu 24.04 server, then:

```bash
sudo ./install.sh
```

That will:

1. Install FreeRADIUS 3.0, `freeradius-utils`, Docker, and the Docker Compose plugin.
2. Back up the stock FreeRADIUS config to `/root/freeradius-backup-TIMESTAMP`.
3. Write a starter `clients.conf` with a localhost client. The secret is generated at install time and stored in `/opt/radius-admin/data`.
4. Enable the `files` module and make sure the `Mikrotik-Group` attribute is available.
5. Start Easy Radius on port **8088**.

The installer writes FreeRADIUS files as `freerad:freerad` mode `0640` (new directories `0750`). When it edits a file that already exists, it keeps that file's owner and mode. It then runs `sudo -u freerad freeradius -XC`, the same user the service uses, and only then restarts FreeRADIUS. If the restart fails, the installer prints the last journal lines and puts the previous config back.

Read the admin password once:

```bash
sudo docker logs radius-admin
```

The username is `neill`. A root-only copy is also written to `/opt/radius-admin/data/initial-admin-password.txt`. Delete that file after you have saved the password.

Change it later on the Security page (current password, then the new one twice, at least 12 characters). If the password is lost:

```bash
sudo docker exec -it radius-admin python -m easy_radius.reset_admin_password
```

That stores only a hash and signs out existing browsers.

Open `http://<server>:8088`, add routers and users, then click **Apply**.

### Firewall

The container uses host networking, so it listens on the host's port 8088. `ufw` applies to that port the same way it applies to any other host service. Docker does not bypass the firewall for this port.

Enable the firewall in the same install, or run it again later. Rules are added before `ufw` is turned on. If the current SSH client would be locked out, the script stops and does not enable `ufw`.

```bash
sudo ./install.sh --ufw \
  --admin-subnets 192.0.2.0/24 \
  --router-subnets 198.51.100.0/24
```

Replace those documentation ranges with your own.

- `--admin-subnets` may open TCP 22 and TCP 8088. If you omit it, the script uses the current SSH client as a single host (`/32` or `/128`).
- `--router-subnets` may open UDP 1812 and UDP 1813. If you omit it, RADIUS ports stay closed.

## Existing server

Use the same command:

```bash
sudo ./install.sh
```

If `/etc/freeradius/3.0/clients.conf` is already there, the script:

- copies the current FreeRADIUS config to `/root/freeradius-backup-TIMESTAMP`
- does **not** overwrite `clients.conf` or the users file
- does **not** import routers or users into the web UI
- does add the login and accounting log modules, then restarts FreeRADIUS only if `freeradius -XC` passes

The UI starts empty. Add every router and user yourself, then click **Apply**. Apply writes new files (including a localhost client for `radtest`), runs `freeradius -XC`, and restarts FreeRADIUS only when the check passes. If the check fails, the previous files are put back.

Package upgrades during install keep the existing config files (`--force-confold`).

## What the pages do

- **Routers.** Site name, IP, secret, and a green or red status from the last RADIUS packet (green if one arrived in the last 15 minutes). Secrets stay hidden until you click Show. Disable a router instead of deleting it. **Copy MikroTik config** shows, only after you click, the RouterOS commands with that router's secret filled in. The commands set `src-address` to the router IP stored here, which must be an address the router itself owns. Without that, a router behind NAT can send from a public address FreeRADIUS does not know, and the packet is ignored. Set "This server's address" first; that address is what the router should use. The second command updates a RADIUS entry that is already on the router.
- **Users.** Username, group `full` / `write` / `read` (`Mikrotik-Group`), and access. The password is stored only as two hashes: SHA-512 crypt (`$6$`) for PAP, and an NT hash for MS-CHAP / MS-CHAPv2. It cannot be shown again. **Set new password** replaces both. Access is **All routers** unless you choose routers or a site group. A site group is a tag on the router, such as `North`. Disable a user instead of deleting them. Disabled routers and users are left out of the files Apply writes. A restricted user is rejected on any other router. The check uses the packet source address and the client shortname, so a router cannot pretend to be another site. The Test page can still imitate a router from this server by setting NAS-IP-Address. SSH logins and `radtest` use PAP. MikroTik Winbox uses MS-CHAPv2. A user saved when only the crypt hash was stored cannot be converted; the Users page shows **Set password again to enable Winbox/MS-CHAP** until you set the password again.
- **Logins.** Recent Access-Accept and Access-Reject lines, filtered by router, user, and result.
- **Sessions.** Who is logged in now, and recent accounting (start, update, stop).
- **Apply.** Backs up the current files under `/opt/radius-admin/data/backups/<timestamp>/`, writes the generated files, restores each file's owner and mode (new files are `freerad:freerad` mode `0640`), runs `sudo -u freerad freeradius -XC`, then `systemctl restart freeradius` only on success. If the restart fails, Apply prints the journal and puts the previous files back. A successful Apply also keeps a snapshot. An existing install that still has plaintext user passwords hashes them on startup. The users file is rewritten with those hashes on the next Apply.
- **Automation.** Tasks are RouterOS commands (one per line) or YAML or JSON lists of paths to set, such as `/ip dns set servers=192.0.2.53`. Commands are checked for a path, a known verb, key=value pairs, and balanced quotes and brackets before they are saved. The router list and site groups are the inventory. **Check** shows what would change and writes nothing. **Run** sets only the values that differ, after saving `/export` for each router. Routers are done in batches, and a failure stops the next batch. The service account is a RADIUS user. Its password is encrypted in the data file and is not shown after you save it. Only the signed-in admin can run a task. More than one router asks for confirmation. Results are on the run page and in History. API-SSL (port 8729) is required unless that router's form allows the plaintext API on port 8728.
- **Backups.** A nightly `/export` of every enabled router, with a retention period you set. Diff two saved versions. A change Easy Radius did not make is called out in History. Each run keeps a result per router (ok, changed, or failed). A failure is shown on the Backups page and in History, including a refused connection, a missing api-ssl certificate, or a rejected service account.
- **Compliance.** Pass or fail for telnet, FTP, SSH, Winbox, www, www-ssl, the default admin, NTP, a restricted api-ssl, plaintext API, SNMP, and RADIUS login. Service checks include the port, for example `enabled on port 8291, restricted to 192.0.2.0/24`. FTP must be enabled and limited to specific addresses. Winbox passes when it is off, and when it is on but limited to specific addresses. It fails when it is on with no allowed addresses (`0.0.0.0/0` and `::/0` count as no limit). SSH is shown the same way and does not fail. www and www-ssl are separate checks; both must be off. SNMP lists each community's name, addresses, read or write access, and security. It does not show community secrets. It fails when a community named public is enabled, or when an enabled community has write access and no address limit. Plaintext API passes when it is off, and also when it is on but limited to specific addresses. **Fix ticked routers** uses the automation account. It can turn www and www-ssl off. It does not disable the plaintext API, and it does not change FTP or Winbox.
- **Firmware.** Shows RouterOS version, channel, model, and architecture after a refresh. Flags a router that is older than the latest release on that router's own channel (stable, long-term, testing, or development). Upgrade saves `/export` first, then installs on the router's current channel unless you explicitly pick a different one. A failure stops the next batch.
- **Inventory.** Groups routers by site group and shows model, serial, version, channel, uptime, and licence level. Download the same table as CSV.

Third-party licences are listed in [LICENSES.md](LICENSES.md).

- **Test.** Runs `radtest` against `127.0.0.1` with the localhost client secret.
- **History.** Who changed what, and when. **Roll back** on a snapshot puts those routers and users back and applies them.
- **Backup.** Download or restore one passphrase-encrypted file. The passphrase is not stored. A restore replaces routers, users, the localhost secret, authenticator setup, and the admin password. Click Apply afterwards.
- **Monitoring.** A quiet router, high CPU or memory, and a burst of failed logins can email you or message a Telegram bot. SMTP passwords and the bot token are encrypted and are not shown after you save them.
- **Access.** Give one RADIUS user extra routers or a site group for a number of hours. FreeRADIUS is updated at once, and the extra access is removed when the time runs out.
- **Reports.** Download a PDF of that month's changes and login lines. On the first morning of the month a short email notice is sent if email alerts are set.
- **Security.** Change the admin password, and optional authenticator codes for the `neill` login. Leave authenticator codes off if you do not want them. The admin password is stored only as a hash. Changing it signs out other browsers.

`install.sh` enables a FreeRADIUS `linelog` for logins and accounting and hooks it into the site's `post-auth`, reject, and `accounting` sections. It does not replace `clients.conf` or the users file when those already exist. Logs are:

- `/var/log/freeradius/easy-radius-auth.log`
- `/var/log/freeradius/easy-radius-acct.log`

The container mounts `/var/log/freeradius` read-only so the pages can read them. The installer runs `sudo -u freerad freeradius -XC` after it writes files. If that check or the restart fails, it prints the last journal lines, restores the backup from `/root/freeradius-backup-TIMESTAMP`, and stops before Docker starts.

Generated users look like this. Both values are hashes of `example-password`, not the password. `Crypt-Password` is SHA-512 crypt. `NT-Password` is MD4 of the password as UTF-16LE.

```text
alice Crypt-Password := "$6$examplesalt1234$ZvOLEUdnZysdHXmagNW4UQjiz0Gd0YHrrNVCWgqrT4vRLQ9ctjcGMuoQTGZ6b7j1EbVNbmxRGFMZ5TfjLVNNt1", NT-Password := 0xBB7FAFD45FABBDBD035ECD5A7A78C01D
    Mikrotik-Group = "write"
```

FreeRADIUS checks `Crypt-Password` with the `pap` module (SSH and `radtest`) and `NT-Password` with the `mschap` module (Winbox). Both are check items, on the same line as the username. Router secrets stay in `/opt/radius-admin/data/data.json` because FreeRADIUS needs them. User passwords and the admin password are stored only as hashes, including in encrypted backups and History snapshots. The data directory is mode `0700`.

## Uninstall and rollback

Stop the web UI without touching FreeRADIUS:

```bash
sudo ./uninstall.sh
```

Restore the config saved by `install.sh`:

```bash
sudo systemctl stop freeradius
sudo cp -a /root/freeradius-backup-TIMESTAMP/freeradius/. /etc/freeradius/3.0/
sudo systemctl start freeradius
```

Apply keeps its own copies in `/opt/radius-admin/data/backups/`. Those are what the app restores when `freeradius -XC` fails.

To remove the app directory as well (this deletes saved routers, users, and the admin hash):

```bash
sudo ./uninstall.sh --remove-app --yes
```

Firewall rules are left in place. Inspect them with `sudo ufw status numbered` and delete the ones you added with `sudo ufw delete NUMBER`.

FreeRADIUS itself is left installed. Remove it only if you mean to:

```bash
sudo apt-get remove freeradius freeradius-utils
```

## Layout

The app is deployed to `/opt/radius-admin`. `docker-compose.yml` runs the container with `privileged: true`, `pid: host`, and `network_mode: host`, and mounts `/etc/freeradius`, `/var/log/freeradius`, and `./data`. Host commands (`freeradius`, `systemctl`, `radtest`) are run with `nsenter -t 1 -m -u -i -n -p`.

MikroTik commands, for a server at `192.0.2.1`, a router at `192.0.2.10`, and a sample secret, look like this:

```text
/radius add address=192.0.2.1 secret=example-router-secret service=login src-address=192.0.2.10 timeout=3s
/radius set [find address=192.0.2.1] src-address=192.0.2.10 secret=example-router-secret
/user aaa set use-radius=yes
```

## Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```

Tests use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and obvious sample names such as `ExampleSite`. Do not commit the `data/` directory, `.env`, or archives.
