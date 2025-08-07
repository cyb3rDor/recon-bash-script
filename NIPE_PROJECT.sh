#!/bin/bash
sudo apt install figlet -y
figlet "Network Project"

#Colors settings for script
GREEN="\e[0;32m"
RED="\e[0;31m"
STOP="\e[0m"

HOME_DIR="$HOME" #Varaiables settings
LOCAL_DIR="$HOME_DIR/Desktop/Network_Project"
REMOTE_DIR="~/Desktop/Network_Project"
LOG_FILE="$LOCAL_DIR/audit.log"

mkdir -p "$LOCAL_DIR"
echo "[$(date)] Script started." > $LOG_FILE  #script log start

#1.1-1.2 Installing required packages on local machine
REQUIRED_PACKAGES=( "sshpass" "git" "curl" "geoip-bin" "cpanminus" "tor" "nmap" )
echo "[*] Checking local dependencies..."
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    dpkg -s "$pkg" >/dev/null 2>&1 || {
        echo "    Installing $pkg..."
        sudo apt-get install "$pkg" -y >/dev/null 2>&1
    }
    echo "$pkg is installed on remote host."
done

#Installing NIPE
function INSTALL_NIPE() {
    cd "$LOCAL_DIR"

    if [ ! -d "$LOCAL_DIR/nipe" ]; then
        echo "[*] Installing NIPE..."
        git clone https://github.com/htrgouvea/nipe.git nipe >/dev/null 2>&1

        if [ ! -d "$LOCAL_DIR/nipe" ]; then
            printf "${RED}[!] Failed to clone NIPE repository. Exiting.${STOP}\n"
            exit 1
        fi

        cd "$LOCAL_DIR/nipe"
        sudo cpanm --installdeps . >/dev/null 2>&1
        sudo perl nipe.pl install >/dev/null 2>&1
    else
        echo "[*] NIPE already installed."
        cd "$LOCAL_DIR/nipe"
    fi
}

## Start Nipe function
function START_NIPE() {
    cd "$LOCAL_DIR/nipe"
    echo "[*] Starting NIPE..."
    sudo perl nipe.pl restart >/dev/null 2>&1
    sudo perl nipe.pl start >/dev/null 2>&1
    sleep 12 ## due to NIPE is slowly sometimes
}

## 1.3  Check if the network connection is anonymous; if not, alert the user and exit.
function CHECK_ANONYMITY() {
    IP_TOR=$(curl -s --max-time 20 ifconfig.me)
    if [ -z "$IP_TOR" ]; then
        printf "${RED}[!] Failed to retrieve IP. Tor may not be active.${STOP}\n"
        exit 1
    fi

	SPOOFED_COUNTRY=$(geoiplookup "$IP_TOR" | awk -F: '{print $2}' | awk -F "," '{print $2}' | xargs) 

    if [ -z "$SPOOFED_COUNTRY" ] || [ "$SPOOFED_COUNTRY" = "Israel" ]; ## was important to include the -z flag
    then 
        printf "${RED}[!] You are NOT anonymous. Exiting...${STOP}\n"
        echo "[$(date)] Anonymity check failed. IP: $IP_TOR" >> "$LOG_FILE"
        exit 1
    else
        printf "${GREEN}[+] You are anonymous. Spoofed Country: $SPOOFED_COUNTRY${STOP}\n" ##1.14
        echo "[$(date)] Anonymity OK. IP: $IP_TOR ($SPOOFED_COUNTRY)" >> "$LOG_FILE"
    fi
}

#Function calling
INSTALL_NIPE
START_NIPE
CHECK_ANONYMITY

#1.5 Allow the user to specify the address to scan via remote server; save into a variable.
read -p "[*] Enter the IP address to scan: " TARGET_IP
read -p "[*] Enter remote username: " REMOTE_USER
read -p "[*] Enter remote IP: " REMOTE_HOST
read -s -p "[*] Enter remote password: " REMOTE_PASS
echo ""

# New dir on the remote machine + checking for ssh connection.
echo "Generating WHOIS results and NMAP open port scan through the remote server for the ip target: $TARGET_IP " 
if ! sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $REMOTE_DIR" >/dev/null 2>&1; then
    echo -e "${RED}[!] SSH connection failed. Could not create remote directory.${STOP}"
    echo "[$(date)] SSH connection failed. Could not create remote directory on $REMOTE_HOST" >> "$LOG_FILE"
    exit 1
fi
echo "[*] SSH connection success - remote directory created"
## Ensure geoiplookup and update -including nmap.whois- is installed remotely
sshpass -p "$REMOTE_PASS" ssh -tt "$REMOTE_USER@$REMOTE_HOST" "echo '$REMOTE_PASS' | sudo -S apt-get update && echo '$REMOTE_PASS' | sudo -S apt-get install -y geoip-bin" >/dev/null 2>&1

## 2.1 Display the details of the remote server (country, IP, and Uptime).
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "PUBLIC_IP=\$(curl -s ifconfig.me) && COUNTRY=\$(geoiplookup \$PUBLIC_IP | cut -d ',' -f2 | xargs) && UPTIME=\$(uptime) && echo 'Remote Server Info:' && echo \"IP: \$PUBLIC_IP | Country: \$COUNTRY | Uptime: \$UPTIME\""


## 2.2 Get the remote server to check the Whois of the given address.
sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "whois $TARGET_IP > $REMOTE_DIR/whois_result.txt"
echo "WHOAMI scan finished"
echo "[$(date)] WHOAMI scan finished" >> "$LOG_FILE"

## extra function to specify the port scan
echo "[*] Choose scan type for Nmap:"
echo "1) Full scan (all ports)"
echo "2) Normal scan (default 1000 ports)"
echo "3) Fast scan (top 100 ports)"
echo "4) Custom port(s)"
read -p "Enter your choice (1/2/3/4): " SCAN_CHOICE

function PORT_INPUT(){
	case $SCAN_CHOICE in
		1)
			PORT_FLAGS="-p-"
			;;
		2)
			PORT_FLAGS=""
			;;
		3)
			PORT_FLAGS="-F"
			;;
		4) 
			read -p "Enter costume port " COSTUME_PORT
			PORT_FLAGS="-p ${COSTUME_PORT}"
			;;
		*)
            echo -e "${RED}[!] Invalid choice. Please enter 1, 2, 3, or 4.${STOP} Script exit"
			;;
	esac
}

PORT_INPUT

## 2.3 Get the remote server to scan for open ports on the given address.

sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "nmap $PORT_FLAGS --open -T4 $TARGET_IP -oN $REMOTE_DIR/nmap_result.txt" >/dev/null 2>&1

echo "[$(date)] Nmap scan ($PORT_FLAGS) finished on $TARGET_IP" >> "$LOG_FILE"

## 3.1 Copying result from dir on remote host to local host 
sshpass -p "$REMOTE_PASS" scp "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/nmap_result.txt" "$LOCAL_DIR/"
sshpass -p "$REMOTE_PASS" scp "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/whois_result.txt" "$LOCAL_DIR/"
sshpass -p "$REMOTE_PASS" ssh "$REMOTE_USER@$REMOTE_HOST" "rm -r $REMOTE_DIR" ## to leave no trace.


## 3.2 Create a log and audit your data collecting.
echo "[$(date)] Port scan of $PORT_FLAGS Scan completed on target: $TARGET_IP" >> "$LOG_FILE" # log already created dand information was added during thr all script.

## 4. The End - stoping nipe and echo results.
echo "[*] Stopping NIPE..."
cd "$LOCAL_DIR/nipe" && sudo perl nipe.pl stop
echo "[*] Done! Results saved in $LOCAL_DIR and all traces was deleted from the remote machine disk"
echo "[*] Nmap "$PORT_FLAGS" scan saved on: "$LOCAL_DIR" nmap_result.txt"
echo "[*] WHOIS check  saved on: "$LOCAL_DIR" whois_result.txt"
echo "[$(date)] Script completed." >> "$LOG_FILE"




