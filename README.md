# Enhanced Honeypot Detection (Banner + SSH Interaction)

## ⚠️ Disclaimer & Important Notes ⚠️

* **EDUCATIONAL USE ONLY:** This script demonstrates techniques for potentially identifying honeypots and is intended **strictly** for academic and research purposes within controlled, isolated laboratory environments.
* **NETWORK TRAFFIC GENERATED:** Running this script actively connects to the target system, potentially over SSH. This activity **generates network traffic** that is detectable by firewalls, IDS/IPS, NGFWs, and the target system itself. This script *performs* detection; it does not *evade* network monitoring while doing so.
* **RISKS OF INTERACTION:** Attempting SSH logins, even with common default credentials, constitutes interaction with the target system. This may be logged and could be considered unauthorized access depending on the context and rules of engagement. Use responsibly.
* **NOT FOOLPROOF:** This script is **not guaranteed** to detect all honeypots. Well-configured, high-interaction honeypots are designed to mimic real systems closely and can defeat these simple banner and behavioral checks. Conversely, real systems might occasionally exhibit behavior that triggers a false positive (e.g., accepting a default credential temporarily, having unusual banner info).
* **REQUIRES `paramiko`:** The SSH interaction functionality depends on the external `paramiko` library.

## Description

This Python script enhances basic honeypot detection by combining two approaches:

1.  **Banner Analysis:** It first connects to the target IP and port, retrieves the initial service banner (if any), and checks it against a list of known keywords often associated with honeypot software or testing environments.
2.  **SSH Interaction (Behavioral Check):** If the banner analysis is inconclusive *and* the target port is the standard SSH port (22), the script attempts to log in via SSH using a predefined list of common weak/default credentials. If a login succeeds (which is highly suspicious), it then executes a test command sequence (`uname -a && id && echo HONEYPOT_TEST_SUCCESS`) and checks if the command completes successfully and produces expected output. Failure during login (with non-default creds), unexpected command errors, or incomplete command execution are treated as potential honeypot indicators.

The script aims to provide a more robust assessment than banner checking alone by probing the behavior and configuration of the target service.

## Features

* **Banner Keyword Check:** Scans initial service banner for common honeypot identifiers.
* **SSH Login Attempt:** Tries logging in via SSH using a list of common weak/default username/password pairs.
* **SSH Command Execution Test:** If weak login succeeds, runs a test command to check shell fidelity and command emulation depth.
* **Combined Analysis:** Uses results from both banner and SSH interaction (if applicable) to make a detection decision.
* **Configurable:** Target IP/Port, timeouts, banner keywords, and weak credentials can be adjusted.
* **Error Handling:** Includes basic handling for timeouts and connection errors.

## Requirements

* **Python 3:** Script requires Python 3.x.
* **`paramiko` library:** Required for SSH functionality. Install using pip:
    ```bash
    pip install paramiko
    ```
* **Target Service:** A service (e.g., SSH on port 22) running on the target machine (real or a honeypot) for the script to interact with.

## Setup

1.  **Install `paramiko`:** Run `pip install paramiko` on the machine where you will run this script (e.g., Kali).
2.  **Configure Script:**
    * Edit `enhanced_honeypot_detector.py`.
    * Set `TARGET_IP` to the IP address of the target machine (e.g., Victim1).
    * Set `TARGET_PORT` to the port of the service you want to check (e.g., 22 for SSH).
    * Optionally adjust `CONN_TIMEOUT`, `BANNER_TIMEOUT`, `SSH_TIMEOUT`.
    * Optionally modify `BANNER_INDICATORS` or `SSH_WEAK_CREDS` lists.

## Usage

1.  **Run the Script:** Execute from your attacking machine (e.g., Kali):
    ```bash
    python3 enhanced_honeypot_detector.py
    ```
2.  **Observe Output:** The script will print its progress, including:
    * Banner check results.
    * SSH login attempts (if port is 22 and banner check was inconclusive).
    * Command execution results (if weak login succeeded).
    * A final verdict on whether honeypot indicators were detected.

## How It Works

1.  **Banner Check:** `check_banner()` connects, receives initial bytes, decodes, and iterates through `BANNER_INDICATORS`. Returns `True` if a keyword is found, `False` if no keywords found, `None` if an error occurs.
2.  **SSH Interaction Check:** `check_ssh_interaction()` is called only if the banner check returned `False` and `TARGET_PORT` is 22.
    * It iterates through `SSH_WEAK_CREDS`.
    * For each pair, it attempts `paramiko.SSHClient().connect()`.
        * If `AuthenticationException` occurs, it tries the next credential (this is expected for real systems).
        * If other `SSHException` or `socket.timeout` occurs, it might log a warning and potentially indicate suspicion or try the next credential depending on the error.
        * If connection **succeeds**, it's immediately suspicious. It then runs `TEST_COMMAND`.
            * If command execution fails or the output doesn't contain `EXPECTED_STRING_IN_OUTPUT` or the exit status is non-zero, it returns `True` (honeypot suspected).
            * If the command seems to run correctly, it *still* returns `True` because the successful login with weak credentials is the primary indicator.
    * If the loop finishes without successful weak logins or suspicious errors, it returns `False`.
3.  **Main Logic:** The main block calls `check_banner()`. Based on the result, it might call `check_ssh_interaction()`. It then combines the results to print a final decision and simulates subsequent actions or exits.

## Limitations

* **Network Detectability:** All actions (connection, banner grab, SSH login, command execution) are network events detectable by monitoring tools.
* **Advanced Honeypots:** High-interaction honeypots or those specifically configured to avoid default credentials and accurately emulate services (including command output) can defeat this script.
* **Real Systems:** A real system misconfigured to allow a default credential would be flagged as a honeypot by the SSH check. A real system with an unusual banner containing a keyword might trigger a false positive.
* **Limited Protocol Support:** The interaction check is currently implemented only for SSH (port 22). Detecting honeypots for other protocols (HTTP, FTP, Telnet, etc.) would require different interaction logic specific to those protocols.
* **`paramiko` Quirks:** SSH interaction can sometimes be complex; different server implementations or `paramiko` limitations might lead to unexpected errors.