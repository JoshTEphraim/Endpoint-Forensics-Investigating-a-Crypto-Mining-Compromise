# Endpoint Forensics: Investigating a Crypto-Mining Compromise

Welcome back, my aspiring digital forensic investigators!

The world of cybercrime continues to evolve, and attackers are constantly finding creative ways to exploit systems without the victim ever noticing. One increasingly common threat is **crypto-jacking** where attackers silently hijack a system's processing power to mine cryptocurrency for themselves. The victim pays the electricity bill while the attacker earns the reward.

The tool most commonly associated with this threat is **XMRig**, a high-performance open-source CPU and GPU miner. On its own, XMRig is a legitimate piece of software. In the hands of an attacker, it becomes a trojan, quietly installed, disguised as something harmless like an Adobe update, and left running in the background indefinitely.

Unlike ransomware, XMRig doesn't encrypt your files or steal your credentials. It just sits there, draining your resources and costing you money while making the attacker rich.

Today, we are going to investigate a compromised Linux system where unexpected configuration changes and unfamiliar files were found in critical directories. We have been given a single disk image file and our job is to determine if a compromise occurred, identify the tactics used, assess the impact, and recommend how to fix it.

---

# Examining the Disk Image

We begin by understanding what we are working with. Running the `file` command against the image tells us its type:

```bash
file disk_image.img
```

The output confirms it is a DOS/MBR boot sector image with an extended partition table.

To dig deeper into its partition structure, we use `fdisk`:

```bash
sudo fdisk -l disk_image.img
```

The output reveals two partitions:

- The first is a small 1MB BIOS boot partition. Nothing useful there.
- The second is an 8GB Linux filesystem and that is where our evidence lives.

To mount a specific partition from a disk image, we need to calculate its byte offset.

Think of the disk image like a book. The offset is the exact page number where our chapter begins.

```text
Offset = Sector Size × Partition Start

512 × 4096 = 2,097,152
```

We create our mount point and mount the partition read-only:

```bash
sudo mkdir /mnt/evidence

sudo mount -o ro,loop,offset=2097152,noload \
disk_image.img /mnt/evidence
```

The `noload` flag tells the system to skip the filesystem journal. This is necessary because the disk may have been powered off abruptly without a clean shutdown.

No output means success. We are in.

---

# Attacker Reconnaissance

Inside `/mnt/evidence`, the first place we check is `.bash_history`.

This file logs every command the user executed and is often a goldmine for forensic investigators.

The history immediately reveals that the user `noah` was added to the `sudo` group, a textbook privilege escalation move that grants the attacker elevated access.

To cover these tracks, the attacker then deleted the authentication log entirely:

```bash
sudo rm -f /var/log/auth.log
```

Deleting `auth.log` removes evidence of every login attempt and authentication event on the system.

The attacker knew exactly what they were doing.

---

# Persistence via Scheduled Task

Once inside, attackers rarely rely on a single foothold. They plant something that survives reboots and reconnects them automatically.

Scheduled tasks, known as cron jobs on Linux, are a favourite hiding spot.

Cron jobs are stored in:

```text
/var/spool/cron/crontabs/
```

This is a sticky directory where only the owner can modify files.

Accessing it requires root privileges.

Inside, we find a scheduled task configured to run every hour from the `/tmp` folder, an immediate red flag.

The `/tmp` directory is meant for temporary files, not backup jobs.

The scheduled file is `backup.elf`, an ELF binary, Linux's equivalent of a Windows `.exe`.

![Cron Job Evidence](https://private-user-images.githubusercontent.com/120121423/589576884-ddfebf24-6cf7-4944-9584-75352fa905bd.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NzgyNDg0NTEsIm5iZiI6MTc3ODI0ODE1MSwicGF0aCI6Ii8xMjAxMjE0MjMvNTg5NTc2ODg0LWRkZmViZjI0LTZjZjctNDk0NC05NTg0LTc1MzUyZmE5MDViZC5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjYwNTA4JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI2MDUwOFQxMzQ5MTFaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0xNThlM2FhYmYyZmFiOTgzMWIwYjk1ZmY4YmQyZjljZTU0N2M2NzAxYjU3ZTYwNDk1YTI0ZDQ0Yjg1YjdkOTM1JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCZyZXNwb25zZS1jb250ZW50LXR5cGU9aW1hZ2UlMkZwbmcifQ.eLIuO7Q1HVUYbvOLeU2UH5lcm__0hqIDhXCDNqDwmGQ)

---

# Confirming the Malware

With the file located, we extract its MD5 hash and submit it to VirusTotal.

The results are definitive:

- 33 out of 64 vendors flag the file as malicious
- The malware belongs to the Mirai family
- Categorised as a Trojan
- Identified as `xmr_linux_amd64`

This confirms the file is an XMRig crypto miner disguised as a backup utility.

---

# Recovering Deleted Evidence

The attacker deleted their `.bash_history` to hide how `backup.elf` was downloaded onto the system.

Deleted doesn't mean gone.

We use PhotoRec, a file carving tool that recovers deleted files from disk images by scanning for recognizable file signatures:

```bash
sudo photorec disk_image.img
```

Once recovery completes, we search the recovered files for any reference to our malicious binary:

```bash
grep -r "/tmp/backup.elf"
```

A match surfaces in:

```text
recup_dir.22/f4628416.elf
```

Running `strings` on this file and filtering for download tools reveals the exact URL on the attacker's server where `backup.elf` was hosted, the staging point for the entire operation.

---

# Exfiltration

The attacker didn't just install a miner and leave.

They also stole data.

Searching the recovered ELF strings for `scp`, a tool used to transfer files between systems over SSH, reveals a list of sensitive files that were quietly copied to the attacker's remote server.

The victim's data left the building without a single alert being triggered.

---

# Privilege Escalation

Examining the `sudoers` file uncovers one more layer of persistence.

The attacker added:

```bash
!tty_tickets
```

to `/etc/sudoers`.

Under normal configuration, a sudo session is tied to a single terminal.

With `!tty_tickets` disabled, a single successful authentication carries across every open terminal session simultaneously, giving the attacker a persistent, elevated foothold across the entire system.

---

# Lateral Movement

The final piece of the puzzle is understanding how the attacker first got in.

Searching the recovered ELF strings for SSH authentication events reveals repeated login failures from:

```text
192.168.19.147
```

This was an SSH brute-force attack targeting the root account.

The attacker hammered the system with credential attempts until one worked.

On:

```text
October 28 at 15:35:21
```

the attack succeeded and the attacker gained their first foothold.

---

# Timeline

The attack began with an SSH brute-force attack from `192.168.19.147`, eventually cracking the root password and gaining initial access.

From there, the attacker performed quiet reconnaissance using native system tools such as `whoami`, `net`, and others to map out the environment.

They escalated privileges by:

- Adding the user `noah` to the sudo group
- Modifying the `sudoers` file

This ensured their elevated access persisted across all terminal sessions.

To maintain a reliable backdoor, they planted a crypto-mining ELF binary disguised as a backup file in `/tmp` and scheduled it to run every hour via cron.

Sensitive files were then exfiltrated to the attacker's server using `scp`.

Finally, the attacker covered their tracks by deleting:

- `auth.log`
- `.bash_history`

before leaving the miner to run silently in the background.

---

# Summary

| Stage | Technique |
|---|---|
| Initial Access | SSH Brute Force |
| Execution | XMRig crypto miner (ELF binary) |
| Persistence | Cron job in `/tmp` |
| Privilege Escalation | Added user to sudo group; modified sudoers |
| Defense Evasion | Deleted `auth.log` and `.bash_history` |
| Exfiltration | `scp` to attacker-controlled server |

---

# Conclusion

Crypto-jacking attacks are designed to be invisible.

No ransom note, no locked screen, just a silent drain on your resources.

Forensics gives us the ability to reconstruct what happened long after the attacker tried to erase their steps.

By following the traces left in cron jobs, recovered files, and system logs, we can expose the full picture.
