#!/usr/bin/env python3
"""
Greatly Enhanced Honeypot Detection via Banner, Interaction & Behavioral Analysis

Connects to a target service (primarily SSH), checks banner/protocol details,
attempts SSH login with common weak credentials, executes test commands,
analyzes command fidelity, and measures response timing variations
to identify potential honeypots, including interactive simulations.

NOTE: Generates detectable network traffic. For lab/educational use only.
      Requires 'paramiko' library (`pip install paramiko`).
"""
import socket
import time
import sys
import statistics

# Attempt to import paramiko
try:
    import paramiko
except ImportError:
    print("[!] Error: 'paramiko' library not found. Run 'pip install paramiko'")
    sys.exit(1)

# --- Configuration ---
# !! ADJUST THESE TO MATCH THE TARGET !!
TARGET_IP = "127.0.0.1"        # Target IP (Victim1 or where honeypot.py runs)
# Honeypot runs SSH on 2222, adjust if needed
TARGET_PORTS = [22, 2222, 23, 2323] # Ports to check (Add honeypot's SSH port!)
CHECK_INTERACTION_ON_PORTS = [22, 2222] # Only perform SSH interaction checks on these ports

CONN_TIMEOUT = 5              # Socket connection timeout (slightly increased)
BANNER_TIMEOUT = 5            # Banner read timeout (slightly increased)
SSH_TIMEOUT = 8               # SSH connection/command timeout (increased for potential delays)
INTER_COMMAND_DELAY = 0.5     # Small delay between sending commands

# Honeypot indicators in banners (Less reliable against advanced honeypots)
BANNER_INDICATORS = [
    "honeypot", "cowrie", "honeyd", "kippo", "decoy", "glastopf",
    "dionaea", "amun", "telnet/debian", "glutton", "hfish",
    "sector/labs", # Used by some research honeypots
]

# Common weak/default credentials often accepted by honeypots
SSH_WEAK_CREDS = [
    ("root", "root"),
    ("admin", "admin"),
    ("root", "password"),
    ("admin", "password"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("ubnt", "ubnt"),
    ("root", "12345"),
    ("admin", "12345"),
    ("support", "support"),
    ("default", "default"),
    # Add more if needed
]

# Command to test basic shell execution - expects specific output/behavior
# Using a simpler command first to establish baseline
INITIAL_TEST_COMMAND = "echo HONEYPOT_TEST_MARKER"
EXPECTED_INITIAL_OUTPUT = "HONEYPOT_TEST_MARKER"

# Commands to test shell fidelity and look for inconsistencies
FIDELITY_COMMANDS = [
    {"cmd": "uname -a", "expect_substr": "Linux", "desc": "Check OS Kernel"}, # Expect "Linux" or similar
    {"cmd": "id", "expect_substr": "uid=", "desc": "Check User ID"},           # Expect "uid="
    # Attempt file write/read/delete - often fails on simple honeypots
    {"cmd": "echo test_content > /tmp/.honey_test && cat /tmp/.honey_test && rm /tmp/.honey_test", "expect_substr": "test_content", "desc": "Test tmp write/read"},
    # Check for common system directories/files
    {"cmd": "ls /etc/passwd", "expect_substr": "/etc/passwd", "desc": "Check /etc/passwd existence"},
    {"cmd": "ls /proc/cpuinfo", "expect_substr": "/proc/cpuinfo", "desc": "Check /proc/cpuinfo existence"}, # Simple honeypots might lack /proc
    # Check process list - honeypots often have suspiciously few processes
    {"cmd": "ps aux", "expect_substr": "PID", "desc": "Check process list"}, # Expect header like PID TTY...
]

# Behavioral Analysis Parameters
TIMING_TEST_COMMAND = "pwd" # Simple command for timing tests
TIMING_REPETITIONS = 5       # How many times to run the timing command
TIMING_STDDEV_THRESHOLD = 0.3 # Std Dev threshold for response times (seconds). High variation is suspicious.
TIMING_MAX_AVG_THRESHOLD = 1.5 # Maximum average response time threshold (seconds). Very slow could be honeypot.
# ---------------------

def check_banner_and_protocol(target_ip, target_port):
    """
    Checks the initial banner/protocol handshake for known indicators or anomalies.
    Returns detection status: True (Honeypot DETECTED), False (Looks Clear), None (Error/Inconclusive).
    """
    print(f"[*] Checking banner/protocol on {target_ip}:{target_port}...")
    start_time = time.time()
    try:
        # Basic Socket Connection for initial banner grab (covers non-SSH too)
        with socket.create_connection((target_ip, target_port), timeout=CONN_TIMEOUT) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            try:
                banner_bytes = sock.recv(1024) # Read initial data
                duration = time.time() - start_time
                print(f"[DEBUG] Initial connection+recv took {duration:.4f}s")
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                 print(f"[WARN] Timeout receiving initial banner from {target_ip}:{target_port}.")
                 # Timeout itself isn't proof, could be slow network/server
                 return False # Treat as inconclusive for banner check specifically
            except Exception as decode_err:
                print(f"[WARN] Could not decode banner: {decode_err}. May be binary protocol.")
                banner = "" # Cannot analyze text banner

            if banner:
                print(f"[DEBUG] Received banner:\n{banner}\n" + "-"*20)
                for indicator in BANNER_INDICATORS:
                    if indicator.lower() in banner.lower():
                        print(f"[DETECTED] Honeypot keyword '{indicator}' found in banner.")
                        return True # Honeypot detected by banner keyword

                # Check for suspiciously short/generic banners sometimes used by simple honeypots
                if len(banner) < 15 and ("welcome" in banner.lower() or "login" in banner.lower()):
                     print(f"[SUSPICIOUS] Very short/generic banner found: '{banner}'. Could be honeypot.")
                     # Don't return True yet, needs more evidence
            else:
                print("[INFO] No text banner received or banner empty.")

        # If it's a potential SSH port, use Paramiko for a more detailed look
        if target_port in CHECK_INTERACTION_ON_PORTS:
            print("[INFO] Attempting Paramiko SSH connection for protocol version info...")
            ssh_client = None
            try:
                # Use Transport for early protocol info without full auth attempt
                transport = paramiko.Transport((target_ip, target_port))
                transport.set_log_channel('paramiko.transport') # Enable some logging for debug
                paramiko_logger = logging.getLogger("paramiko.transport")
                paramiko_logger.setLevel(logging.WARNING) # Adjust level as needed (INFO/DEBUG for more detail)

                transport.connect(hostkey=None, username=None, password=None, timeout=SSH_TIMEOUT) # Host key check happens later

                # Get remote version string reported during SSH handshake
                remote_version = transport.get_remote_server_key() # Actually gets host key info, but version is logged
                server_banner = transport.remote_version # The SSH version string like SSH-2.0-OpenSSH_8.2p1
                transport.close()

                if server_banner:
                    print(f"[DEBUG] Paramiko received SSH server version: {server_banner}")
                    # Check banner indicators again on the SSH version string
                    for indicator in BANNER_INDICATORS:
                        if indicator.lower() in server_banner.lower():
                            print(f"[DETECTED] Honeypot keyword '{indicator}' found in SSH version string.")
                            return True
                    # Check for known vulnerable/old/uncommon versions often emulated
                    if "dropbear" in server_banner.lower() and "2012" in server_banner: # Example check
                         print(f"[SUSPICIOUS] Detected potentially old/emulated Dropbear version: {server_banner}")
                    # Add more specific version checks if needed

                else:
                    print("[WARN] Paramiko did not retrieve a clear SSH server version string.")
                return False # No definite indicators found in protocol check

            except paramiko.SSHException as ssh_err:
                 print(f"[WARN] Paramiko SSH protocol error during initial connection: {ssh_err}. Could indicate honeypot non-standard behavior.")
                 # Non-standard SSH behavior is suspicious
                 return True # Consider this a detection
            except socket.timeout:
                 print(f"[WARN] Timeout during Paramiko SSH connection attempt for {target_ip}:{target_port}.")
                 return None # Inconclusive due to timeout
            except Exception as e:
                print(f"[ERROR] Error during Paramiko SSH protocol check for {target_ip}:{target_port}: {e}")
                return None # Other error, inconclusive
            finally:
                 if ssh_client: ssh_client.close()
                 if 'transport' in locals() and transport.is_active(): transport.close()

        # If not an SSH port check and banner analysis passed
        print(f"[INFO] No definitive honeypot indicators found in banner/protocol for port {target_port}.")
        return False # No indicators found

    except socket.timeout:
        print(f"[WARN] Timeout connecting to {target_ip}:{target_port}.")
        return None # Connection timed out, inconclusive
    except ConnectionRefusedError:
         print(f"[INFO] Connection refused by {target_ip}:{target_port}.")
         return False # Service not running or blocked, likely not a honeypot *on this port*
    except Exception as e:
        print(f"[ERROR] Error during banner/protocol check for {target_ip}:{target_port}: {e}")
        return None # Other error, inconclusive

def perform_ssh_interaction(target_ip, target_port):
    """
    Attempts SSH login with weak creds, runs test commands, checks fidelity,
    and analyzes timing behavior.
    Returns True if honeypot behavior suspected, False otherwise, None on error.
    """
    print(f"\n[*] Starting SSH Interaction & Behavioral Analysis on {target_ip}:{target_port}...")

    detection_reason = None # Store the reason for detection

    for username, password in SSH_WEAK_CREDS:
        print(f"\n[INFO] Trying SSH login: {username}:{password}...")
        ssh_client = None # Ensure client is defined for finally block
        try:
            ssh_client = paramiko.SSHClient()
            # WARNING: Automatically adding host key is insecure but needed for unknown hosts in lab!
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_start_time = time.time()
            ssh_client.connect(
                hostname=target_ip,
                port=target_port,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT,
                banner_timeout=SSH_TIMEOUT, # Paramiko uses banner_timeout during connection too
                auth_timeout=SSH_TIMEOUT,
                look_for_keys=False, # Don't use local SSH keys
                allow_agent=False    # Don't use SSH agent
            )
            connect_duration = time.time() - connect_start_time
            print(f"[DEBUG] SSH connection successful ({username}:{password}) took {connect_duration:.4f}s.")

            # <<< DETECTION POINT 1: Successful login with weak credentials >>>
            # This is highly suspicious and a strong indicator for many honeypots.
            detection_reason = f"Successful SSH login with weak credentials: {username}:{password}"
            print(f"[DETECTED] {detection_reason}")

            # --- Behavioral Analysis: Command Timing ---
            print(f"[*] Performing command timing analysis (running '{TIMING_TEST_COMMAND}' {TIMING_REPETITIONS} times)...")
            response_times = []
            timing_errors = 0
            for i in range(TIMING_REPETITIONS):
                time.sleep(INTER_COMMAND_DELAY) # Small pause between commands
                cmd_start_time = time.time()
                try:
                    stdin, stdout, stderr = ssh_client.exec_command(TIMING_TEST_COMMAND, timeout=SSH_TIMEOUT)
                    exit_status = stdout.channel.recv_exit_status() # Wait for command
                    cmd_end_time = time.time()
                    if exit_status == 0:
                        response_times.append(cmd_end_time - cmd_start_time)
                    else:
                         print(f"[WARN] Timing command exit status {exit_status} on iteration {i+1}")
                         timing_errors += 1
                except Exception as timing_err:
                     print(f"[WARN] Error executing timing command on iteration {i+1}: {timing_err}")
                     timing_errors += 1
                     # Break if too many errors occur during timing
                     if timing_errors > TIMING_REPETITIONS // 2:
                         print("[WARN] Too many errors during timing test, aborting timing analysis.")
                         break

            if len(response_times) >= 3 : # Need at least 3 data points for meaningful stats
                avg_time = statistics.mean(response_times)
                std_dev = statistics.stdev(response_times) if len(response_times) > 1 else 0
                print(f"[DEBUG] Timing results: Avg={avg_time:.4f}s, StdDev={std_dev:.4f}s, Times={response_times}")

                # <<< DETECTION POINT 2: High timing variation (adaptive delays) >>>
                if std_dev > TIMING_STDDEV_THRESHOLD:
                     detection_reason = f"High standard deviation in command response times ({std_dev:.4f}s > {TIMING_STDDEV_THRESHOLD}s), suggesting adaptive delays."
                     print(f"[DETECTED] {detection_reason}")
                     ssh_client.close()
                     return True # Honeypot detected based on timing

                # <<< DETECTION POINT 3: Consistently very slow responses >>>
                if avg_time > TIMING_MAX_AVG_THRESHOLD:
                    detection_reason = f"Average command response time is very high ({avg_time:.4f}s > {TIMING_MAX_AVG_THRESHOLD}s), potentially simulated environment."
                    print(f"[DETECTED] {detection_reason}")
                    ssh_client.close()
                    return True # Honeypot detected based on slowness

            elif timing_errors > 0:
                print("[WARN] Could not reliably perform timing analysis due to command errors.")
            else:
                 print("[INFO] Timing analysis did not show significant variation or excessive delay.")


            # --- Interaction Analysis: Command Fidelity ---
            print(f"[*] Performing command fidelity checks...")

            # Initial simple command
            print(f"  - Executing initial test: '{INITIAL_TEST_COMMAND}'")
            try:
                stdin, stdout, stderr = ssh_client.exec_command(INITIAL_TEST_COMMAND, timeout=SSH_TIMEOUT)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode('utf-8', errors='ignore').strip()
                err_output = stderr.read().decode('utf-8', errors='ignore').strip()

                print(f"[DEBUG] Initial command exit status: {exit_status}")
                print(f"[DEBUG] Initial command stdout: '{output}'")
                if err_output: print(f"[DEBUG] Initial command stderr: '{err_output}'")

                # <<< DETECTION POINT 4: Initial command failure/incorrect output >>>
                if exit_status != 0:
                     detection_reason = f"Initial test command ('{INITIAL_TEST_COMMAND}') failed with exit status {exit_status}."
                     print(f"[DETECTED] {detection_reason}")
                     ssh_client.close()
                     return True
                if EXPECTED_INITIAL_OUTPUT not in output:
                     detection_reason = f"Expected string '{EXPECTED_INITIAL_OUTPUT}' not found in initial command output."
                     print(f"[DETECTED] {detection_reason}")
                     ssh_client.close()
                     return True

            except Exception as cmd_err:
                 detection_reason = f"Error executing initial command '{INITIAL_TEST_COMMAND}': {cmd_err}. Highly suspicious."
                 print(f"[DETECTED] {detection_reason}")
                 ssh_client.close()
                 return True # Failure to execute basic command is suspect

            # Fidelity commands loop
            for test in FIDELITY_COMMANDS:
                print(f"  - Executing fidelity test ({test['desc']}): '{test['cmd']}'")
                time.sleep(INTER_COMMAND_DELAY) # Small pause
                try:
                    stdin, stdout, stderr = ssh_client.exec_command(test['cmd'], timeout=SSH_TIMEOUT)
                    exit_status = stdout.channel.recv_exit_status() # Wait for command
                    output = stdout.read().decode('utf-8', errors='ignore').strip()
                    err_output = stderr.read().decode('utf-8', errors='ignore').strip()

                    print(f"[DEBUG]   Exit Status: {exit_status}")
                    # Only print stdout/stderr if they contain something interesting
                    if output and len(output) < 200: print(f"[DEBUG]   Stdout: {output[:200]}{'...' if len(output) > 200 else ''}")
                    elif output: print(f"[DEBUG]   Stdout: (received {len(output)} bytes)")
                    if err_output: print(f"[DEBUG]   Stderr: {err_output}")

                    # <<< DETECTION POINT 5: Fidelity command failure/incorrect output >>>
                    # Allow non-zero exit for some commands (e.g., ls on non-existent file), but check output
                    if exit_status != 0 and "No such file or directory" not in err_output and "command not found" not in err_output:
                         detection_reason = f"Fidelity command '{test['cmd']}' exited unexpectedly with status {exit_status} and stderr: '{err_output}'."
                         print(f"[DETECTED] {detection_reason}")
                         ssh_client.close()
                         return True
                    if test.get('expect_substr') and test['expect_substr'].lower() not in output.lower() and test['expect_substr'].lower() not in err_output.lower():
                        detection_reason = f"Expected substring '{test['expect_substr']}' not found for command '{test['cmd']}'."
                        print(f"[DETECTED] {detection_reason}")
                        # Specific check for 'ps' - honeypots might return *very* few lines
                        if test['cmd'] == "ps aux" and len(output.splitlines()) < 5:
                             print(f"[SUSPICIOUS] 'ps aux' output has very few lines ({len(output.splitlines())}). Typical for honeypots.")
                             detection_reason += " (Suspiciously few processes)"
                        ssh_client.close()
                        return True
                    if "command not found" in err_output.lower() or "command not found" in output.lower():
                         detection_reason = f"Fidelity command '{test['cmd']}' resulted in 'command not found'. Likely limited shell."
                         print(f"[DETECTED] {detection_reason}")
                         ssh_client.close()
                         return True

                    print(f"[INFO] Fidelity check for '{test['cmd']}' passed.")

                except Exception as cmd_err:
                    # <<< DETECTION POINT 6: Error executing fidelity command >>>
                    detection_reason = f"Error executing fidelity command '{test['cmd']}': {cmd_err}. Environment likely fake."
                    print(f"[DETECTED] {detection_reason}")
                    ssh_client.close()
                    return True # Failure to execute more complex commands is suspect

            # If we got here after successful weak login, all fidelity checks passed.
            # The weak login itself remains the primary detection reason.
            print("[INFO] Command fidelity checks completed without definitive errors, but weak login is suspicious.")
            ssh_client.close()
            return True # Return True because weak login succeeded

        except paramiko.AuthenticationException:
            print(f"[INFO] Authentication failed for {username}:{password}. (Expected for real systems)")
            # Failed auth is normal, continue trying other credentials
            continue # To next credential
        except paramiko.SSHException as ssh_err:
             # <<< DETECTION POINT 7: SSH Protocol Errors during Auth/Session >>>
             # These often indicate non-standard implementation.
             detection_reason = f"SSH protocol error for {username}:{password}: {ssh_err}. Suspicious."
             print(f"[DETECTED] {detection_reason}")
             if ssh_client: ssh_client.close()
             return True # Treat SSH protocol errors as detection
        except socket.timeout:
            print(f"[WARN] Timeout during SSH connection/auth for {username}:{password}.")
            # Timeout might indicate honeypot delaying or network issue. Don't call it detected just for this.
            continue # Try next credential
        except Exception as e:
            print(f"[ERROR] Unexpected error during SSH attempt for {username}:{password}: {e}")
            # Log unexpected errors but don't immediately assume honeypot
            continue # Try next credential
        finally:
             if ssh_client:
                 ssh_client.close()

    # If loop finishes without successful weak login or suspicious error/behavior
    print("[INFO] No successful weak SSH logins or other definitive honeypot behaviors detected via interaction.")
    return False


# --- Main Execution ---
if __name__ == '__main__':
    print("="*60)
    print(" Starting Enhanced Honeypot Detection")
    print(f" Target IP:      {TARGET_IP}")
    print(f" Target Ports:   {TARGET_PORTS}")
    print(f" Interaction on: {CHECK_INTERACTION_ON_PORTS}")
    print("="*60)

    overall_honeypot_detected = False
    final_detection_reason = "No definitive indicators found."

    # Iterate through specified ports
    for port in TARGET_PORTS:
        print(f"\n--- Checking Port {port} ---")
        honeypot_detected_on_port = False
        inconclusive_on_port = False

        # 1. Check Banner / Protocol
        banner_protocol_result = check_banner_and_protocol(TARGET_IP, port)

        if banner_protocol_result is True:
            honeypot_detected_on_port = True
            overall_honeypot_detected = True
            final_detection_reason = f"Detected via banner/protocol analysis on port {port}."
            print(f"[PORT {port} VERDICT] Honeypot DETECTED (Banner/Protocol).")
            # Option: Stop checking other ports once one is detected?
            # break # Uncomment to stop after first detection

        elif banner_protocol_result is None:
             print(f"[PORT {port} INFO] Banner/protocol check inconclusive due to errors.")
             inconclusive_on_port = True
             # Decide whether to proceed with interaction if banner check fails inconclusively
             # For SSH ports, interaction check might still reveal issues
             if port not in CHECK_INTERACTION_ON_PORTS:
                  continue # Skip interaction if not designated SSH port and banner failed

        # 2. Perform Interaction Check (if applicable and not already detected/inconclusive)
        if port in CHECK_INTERACTION_ON_PORTS and not honeypot_detected_on_port:
            if inconclusive_on_port:
                print("[INFO] Proceeding with interaction check despite inconclusive banner check...")

            interaction_result = perform_ssh_interaction(TARGET_IP, port)
            if interaction_result is True:
                honeypot_detected_on_port = True
                overall_honeypot_detected = True
                # The function `perform_ssh_interaction` prints the specific reason.
                final_detection_reason = f"Detected via SSH interaction/behavioral analysis on port {port}."
                print(f"[PORT {port} VERDICT] Honeypot DETECTED (Interaction/Behavior).")
                # break # Uncomment to stop after first detection
            elif interaction_result is None:
                 print(f"[PORT {port} INFO] Interaction check inconclusive due to errors.")
                 inconclusive_on_port = True
            else:
                 # Interaction check returned False (looks clear)
                 print(f"[PORT {port} INFO] Interaction check did not find definitive honeypot indicators.")


        # Summarize port result if not detected
        if not honeypot_detected_on_port:
            if inconclusive_on_port:
                 print(f"[PORT {port} VERDICT] INCONCLUSIVE.")
            else:
                 print(f"[PORT {port} VERDICT] Looks clear.")


    print("\n" + "="*60)
    print(" Overall Honeypot Detection Summary")
    print("="*60)
    # Final Verdict based on checks across all ports
    if overall_honeypot_detected:
        print(f"[FINAL RESULT] Honeypot indicators DETECTED.")
        print(f"[REASON] {final_detection_reason}")
        print("[ACTION] Aborting intended actions is recommended.")
        sys.exit(1) # Exit with non-zero status
    else:
        # Check if any port was inconclusive
        # (Requires tracking inconclusive status across ports, simplified here)
        # A more robust version could track inconclusive ports separately.
        print("[FINAL RESULT] No definitive honeypot indicators found across checked ports.")
        print("                 However, exercise caution if any checks were inconclusive.")
        print("\nSimulating proceeding with caution...")
        # --- Simulated Payload Execution ---
        time.sleep(1)
        print("[PAYLOAD] ...performing actions on target...")
        time.sleep(1)
        print("[PAYLOAD] Finished.")
        # --- End Simulated Payload ---
    print("="*60)
