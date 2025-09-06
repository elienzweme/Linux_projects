# Heritage Automation — Ubuntu VM Quickstart

This guide shows how to install and run **`heritage_automation.sh`** on an **Ubuntu VM** for updates, backups, deployments (via Ansible), and monitoring.

> Works on Ubuntu 22.04+ (and typically 20.04). Requires `sudo` privileges.

---

## 1) Install prerequisites
```bash
sudo apt-get update
sudo apt-get install -y ansible rsync mailutils curl
```
> `python3` is already included on modern Ubuntu.

---

## 2) Get the files onto the VM
**Option A — clone your GitHub repo**
```bash
git clone https://github.com/<your-user>/<your-repo>.git
cd <your-repo>
```

**Option B — copy from your local machine**
```bash
# Example using scp from your laptop
scp -r heritage_automation.sh ansible notify systemd     <your-user>@<vm-ip>:~/
```

---

## 3) Place files in standard locations
```bash
# Main script
sudo install -m 0755 ./heritage_automation.sh /usr/local/sbin/

# Ansible project (inventory + playbooks)
sudo mkdir -p /opt/heritage/ansible
sudo cp -r ./ansible/* /opt/heritage/ansible/

# Notifier (optional but recommended)
sudo install -m 0755 ./notify/heritage_notify.sh /usr/local/lib/

# Inventory in default path so Ansible can find it
sudo mkdir -p /etc/ansible
sudo cp ./ansible/inventory/hosts.ini /etc/ansible/hosts

# Log file used by the script
sudo touch /var/log/heritage_automation.log
sudo chmod 640 /var/log/heritage_automation.log
```

> If your repo uses different paths, adjust the variables at the top of the script:
> `ANSIBLE_INVENTORY`, `ANSIBLE_PLAYBOOK`, `BACKUP_SRC`, `BACKUP_DEST`.

---

## 4) (Optional) Quick test data for backups
```bash
sudo mkdir -p /srv/heritage/data
echo "hello" | sudo tee /srv/heritage/data/example.txt
```

---

## 5) Run once (manual)
**Safe read-only checks:**
```bash
sudo heritage_automation.sh monitor
```

**Full run (updates + backup + deploy + monitoring):**
```bash
sudo heritage_automation.sh --all
```

View logs:
```bash
sudo tail -n 200 /var/log/heritage_automation.log
```

---

## 6) Schedule it (choose one)

### Option A — systemd timers (recommended)
```bash
# If these files are in your repo:
sudo cp ./systemd/heritage_automation.service /etc/systemd/system/
sudo cp ./systemd/heritage_automation.timer   /etc/systemd/system/
sudo cp ./systemd/heritage_monitor.service    /etc/systemd/system/
sudo cp ./systemd/heritage_monitor.timer      /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now heritage_automation.timer   # daily at 02:10 (VM local time)
sudo systemctl enable --now heritage_monitor.timer      # every 5 minutes

# verify
systemctl list-timers | grep heritage
```

### Option B — cron
```bash
sudo crontab -e
# paste lines from CRON_EXAMPLE.txt, for example:
# 10 2 * * * /usr/local/sbin/heritage_automation.sh --all
# */5 * * * * /usr/local/sbin/heritage_automation.sh monitor
```

---

## 7) (Optional) Alerts (email + Slack)
The script auto-loads `/usr/local/lib/heritage_notify.sh` if present and only escalates **WARNING**/**ERROR**. Configure environment vars (survive reboots):
```bash
echo 'EMAIL_TO=ops@example.org' | sudo tee -a /etc/environment
echo 'EMAIL_SUBJECT_PREFIX=[Heritage Automation]' | sudo tee -a /etc/environment
echo 'SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ' | sudo tee -a /etc/environment

sudo systemctl daemon-reload
# timers pick up new env after next start; you can restart them to apply now:
sudo systemctl restart heritage_automation.timer heritage_monitor.timer
```

> Email on fresh VMs may require an MTA/relay. Consider `msmtp` or use Slack only.

---

## 8) Using the sample Ansible playbook
- `[web]` hosts: installs NGINX, serves a simple page.
- `[db]` host: installs and enables PostgreSQL.
- Test on the same VM by adding it under `[web]` in `/etc/ansible/hosts` or point those groups to other hosts.
- If UFW is enabled and you're testing NGINX locally:
```bash
sudo ufw allow 80/tcp
```

---

## 9) Troubleshooting
- **Permission denied** → run with `sudo`.
- **Ansible not found** → `sudo apt-get install -y ansible`.
- **No backups appear** → check `BACKUP_SRC` exists and has files.
- **Playbook errors** → run `ansible -i /etc/ansible/hosts all -m ping` to validate SSH connectivity.
- **Timers not firing** → `systemctl status heritage_automation.timer` and check `journalctl -u heritage_automation.service`.

---

## 10) Disable / Uninstall
```bash
# disable timers
sudo systemctl disable --now heritage_automation.timer heritage_monitor.timer

# remove script and notifier (if desired)
sudo rm -f /usr/local/sbin/heritage_automation.sh /usr/local/lib/heritage_notify.sh

# optional: remove ansible project & logs
# sudo rm -rf /opt/heritage/ansible /var/log/heritage_automation.log
```

---

## Security Notes
- Review the script and playbooks before running them.
- Restrict access to `/usr/local/sbin/heritage_automation.sh` and `/var/log/heritage_automation.log`.
- Store SSH private keys securely (e.g., only in root’s keychain with correct permissions).
- For Slack/email secrets, prefer system environment or systemd drop-ins over plain files in the repo.

---

**That’s it!** Your Ubuntu VM is now ready to run Heritage Automation on-demand or on a schedule.
