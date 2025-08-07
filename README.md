# recon-bash-script
Bash script for automated remote reconnaissance using SSH, NIPE, WHOIS, and Nmap. Built for Cyber Defender training (John Bryce, May 2025).
# 🛰️ Remote Recon Script – Bash Automation

This Bash-based script automates remote reconnaissance operations as part of my Cyber Defender training at John Bryce (May 2025 cohort).

## 🔧 Features
- SSH connection to remote Kali Linux machine
- Enable NIPE to anonymize IP via TOR
- Run WHOIS and Nmap scans from the remote machine
- Save and retrieve scan results securely
- Optional cleanup of traces after scan

## 🗂️ Project Structure
- `network_project.sh` – main Bash script
- `output/` – stores WHOIS and Nmap logs
- `audit.log` – logging system activity

## 🚀 How to Use
1. Make sure required tools are installed: `sshpass`, `geoip-bin`, `curl`, `nmap`, `whois`, `NIPE`
2. Edit the script with your remote IP, SSH credentials, and paths
3. Run the script:
   ```bash
   bash NIPE_PROJECT.sh
