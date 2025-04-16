#!/usr/bin/env python3
"""
Enhanced Honeypot Detection via Banner Analysis & SSH Interaction

Connects to a target service, checks the banner, and if inconclusive,
attempts SSH login with common weak credentials to execute a test command,
analyzing behavior to identify potential honeypots.

NOTE: Generates detectable network traffic. For lab use only.
      Requires 'paramiko' library (`pip install paramiko`).
"""
import socket
import time
import sys

# Attempt to import paramiko
try:
    import paramiko
except ImportError:
    print("[!] Error: 'paramiko' library not found. Run 'pip install paramiko'")
    sys.exit(1)

# --- Configuration ---
TARGET_IP = "192.168.100.101" # Target IP (Victim1)
TARGET_PORT = 22              # Target Port (e.g., SSH)
CONN_TIMEOUT = 4              # Socket connection timeout
BANNER_TIMEOUT = 3            # Banner read timeout
SSH_TIMEOUT = 5               # SSH connection/command timeout

# Honeypot indicators in banners
BANNER_INDICATORS = [
    "honeypot", "cowrie", "honeyd", "kippo", "decoy", "glastopf",
    "dionaea", "amun", "telnet/debian", # Common telnet honeypot default
]

# Common weak/default credentials often accepted by honeypots
# Format: (username, password)
SSH_WEAK_CREDS = [
    ("root", "root"),
    ("admin", "admin"),
    ("root", "password"),
    ("admin", "password"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("ubnt", "ubnt"), # Default for some devices, sometimes in honeypots
    ("root", "12345"),
    ("admin", "12345"),
]

# Command to test shell fidelity - expects specific output/behavior
TEST_COMMAND = "uname -a && id && echo HONEYPOT_TEST_SUCCESS"
EXPECTED_STRING_IN_OUTPUT = "HONEYPOT_TEST_SUCCESS"
# ---------------------


def check_banner(target_ip, target_port):
    """Checks the initial banner for known honeypot keywords. Returns True if found, False otherwise, None on error."""
    print(f"[*] Checking banner on {target_ip}:{target_port}...")
    try:
        with socket.create_connection((target_ip, target_port), timeout=CONN_TIMEOUT) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            banner_bytes = sock.recv(1024) # Read initial data
            try:
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
            except Exception as decode_err:
                print(f"[WARN] Could not decode banner: {decode_err}")
                return None # Cannot analyze banner

            if not banner:
                print("[INFO] No banner received.")
                return False # No banner isn't necessarily a honeypot indicator

            print(f"[DEBUG] Received banner:\n{banner}\n" + "-"*20)

            for indicator in BANNER_INDICATORS:
                if indicator.lower() in banner.lower():
                    print(f"[DETECTED] Honeypot indicator '{indicator}' found in banner.")
                    return True # Honeypot detected by banner

            print("[INFO] No obvious honeypot indicators found in banner.")
            return False # No indicators found

    except socket.timeout:
        print(f"[WARN] Timeout connecting or receiving banner from {target_ip}:{target_port}.")
        return None # Connection timed out, inconclusive
    except ConnectionRefusedError:
         print(f"[INFO] Connection refused by {target_ip}:{target_port}.")
         return False # Service not running or blocked, likely not a honeypot on this port
    except Exception as e:
        print(f"[ERROR] Error during banner check for {target_ip}:{target_port}: {e}")
        return None # Other error, inconclusive


def check_ssh_interaction(target_ip, target_port):
    """Attempts SSH login with weak creds and runs a test command. Returns True if honeypot behavior suspected, False otherwise."""
    print(f"\n[*] Attempting SSH interaction check on {target_ip}:{target_port}...")

    for username, password in SSH_WEAK_CREDS:
        print(f"[INFO] Trying SSH login with {username}:{password}...")
        ssh_client = None # Ensure client is defined for finally block
        try:
            ssh_client = paramiko.SSHClient()
            # WARNING: Automatically adding host key is insecure but needed for unknown hosts in lab!
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh_client.connect(
                hostname=target_ip,
                port=target_port,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT,
                banner_timeout=SSH_TIMEOUT,
                auth_timeout=SSH_TIMEOUT,
                look_for_keys=False, # Don't use local SSH keys
                allow_agent=False    # Don't use SSH agent
            )

            # If login succeeds with weak credentials, it's suspicious
            print(f"[DETECTED] Successful SSH login with weak credentials: {username}:{password}!")

            # Try executing the test command
            print(f"[*] Executing test command: '{TEST_COMMAND}'")
            try:
                stdin, stdout, stderr = ssh_client.exec_command(TEST_COMMAND, timeout=SSH_TIMEOUT)
                exit_status = stdout.channel.recv_exit_status() # Wait for command to finish
                output = stdout.read().decode('utf-8', errors='ignore').strip()
                err_output = stderr.read().decode('utf-8', errors='ignore').strip()

                print(f"[DEBUG] Command exit status: {exit_status}")
                print(f"[DEBUG] Command stdout:\n{output}\n" + "-"*20)
                if err_output:
                     print(f"[DEBUG] Command stderr:\n{err_output}\n" + "-"*20)

                # Analyze command output/behavior
                if exit_status != 0:
                     print(f"[DETECTED] Test command exited with non-zero status ({exit_status}). Suspicious.")
                     return True # Honeypot suspected due to command failure/unexpected exit
                if EXPECTED_STRING_IN_OUTPUT not in output:
                     print(f"[DETECTED] Expected string '{EXPECTED_STRING_IN_OUTPUT}' not found in command output. Suspicious.")
                     return True # Honeypot suspected due to incomplete/incorrect command emulation
                else:
                    # Command executed fully and expected string found - less likely a simple honeypot,
                    # but could still be a high-interaction one. Let's consider successful weak login
                    # itself as the primary indicator here.
                    print("[INFO] Test command executed successfully, but weak login itself is suspicious.")
                    return True # Treat successful weak login as honeypot indicator

            except Exception as cmd_err:
                print(f"[DETECTED] Error executing command via SSH: {cmd_err}. Suspicious.")
                return True # Failure to execute command properly is suspect

        except paramiko.AuthenticationException:
            print(f"[INFO] Authentication failed for {username}:{password}. (Expected for real systems)")
            # Failed auth is normal, continue trying other credentials
            continue
        except paramiko.SSHException as ssh_err:
             print(f"[WARN] SSH protocol error for {username}:{password}: {ssh_err}. Might be honeypot or server issue.")
             # Could indicate honeypot unusual behavior, let's consider it suspicious
             return True
        except socket.timeout:
            print(f"[WARN] Timeout during SSH connection/auth for {username}:{password}.")
            # Timeout might indicate honeypot delaying or network issue
            # Let's not call it a definite honeypot based just on timeout here
            continue # Try next credential
        except Exception as e:
            print(f"[ERROR] Unexpected error during SSH attempt for {username}:{password}: {e}")
            # Unexpected errors might be worth noting but not definitive
            continue # Try next credential
        finally:
             if ssh_client:
                 ssh_client.close()

    # If loop finishes without successful weak login or suspicious error
    print("[INFO] No successful weak SSH logins or suspicious behavior detected.")
    return False


# --- Main Execution ---
if __name__ == '__main__':
    print("="*50)
    print("Starting Enhanced Honeypot Detection...")
    print(f"Target: {TARGET_IP}:{TARGET_PORT}")
    print("="*50)

    honeypot_detected = False

    # 1. Check Banner
    banner_result = check_banner(TARGET_IP, TARGET_PORT)

    if banner_result is True:
        honeypot_detected = True
    elif banner_result is False:
        # Banner looks clean, proceed to interaction check if it's an SSH port
        if TARGET_PORT == 22:
            interaction_result = check_ssh_interaction(TARGET_IP, TARGET_PORT)
            if interaction_result is True:
                honeypot_detected = True
        else:
             print(f"\n[INFO] Interaction check skipped (port {TARGET_PORT} is not standard SSH port 22).")

    # Handle cases where banner check was inconclusive (returned None)
    elif banner_result is None:
         print("\n[INFO] Banner check was inconclusive due to errors. Skipping further checks.")
         # Decide if inconclusive means proceed or abort - here we proceed cautiously
         print("[INFO] Proceeding, but exercise caution.")


    print("\n" + "="*50)
    # Final Verdict
    if honeypot_detected:
        print("[FINAL RESULT] Honeypot indicators DETECTED. Aborting intended actions.")
        sys.exit(1) # Exit with non-zero status
    else:
        print("[FINAL RESULT] No definitive honeypot indicators found.")
        print("                 Proceeding with simulated malicious activity...")
        # --- Simulated Payload Execution ---
        time.sleep(1)
        print("[PAYLOAD] ...performing actions on target...")
        time.sleep(1)
        print("[PAYLOAD] Finished.")
        # --- End Simulated Payload ---
    print("="*50)