#!/usr/bin/env python3
"""
Probabilistic Honeypot Detector via Multi-Factor Analysis

Connects to target services (primarily SSH), analyzes banners, protocol behavior,
authentication acceptance, command execution fidelity, timing variations,
and environment characteristics to generate a honeypot probability score.

NOTE: Generates detectable network traffic. For lab/educational use only.
      Requires 'paramiko' and 'regex' libraries (`pip install paramiko regex`).
"""
import socket
import time
import sys
import statistics
import logging
import re # Using re for regex matching in fidelity checks

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
TARGET_PORTS = [22, 2222] # Ports to check (Focusing on SSH for scoring)
CHECK_INTERACTION_ON_PORTS = [22, 2222] # Only perform SSH interaction checks on these ports

CONN_TIMEOUT = 5
BANNER_TIMEOUT = 5
SSH_TIMEOUT = 10              # Slightly longer for complex commands/timing
INTER_COMMAND_DELAY = 0.5

# --- Scoring Weights ---
# Banner / Protocol Analysis
SCORE_BANNER_KEYWORD = 15
SCORE_BANNER_SUSPICIOUS_GENERIC = 5
SCORE_BANNER_SUSPICIOUS_VERSION = 5
SCORE_PROTOCOL_ERROR_INIT = 30
# Authentication
SCORE_WEAK_LOGIN_SUCCESS = 50 # Strong indicator
# Behavioral Analysis (Timing)
SCORE_TIMING_HIGH_STDDEV_BASE = 15
SCORE_TIMING_HIGH_AVG_BASE = 10
SCORE_TIMING_ERROR = 5
# Interaction Analysis (Command Fidelity)
SCORE_CMD_INITIAL_FAIL = 25
SCORE_CMD_INITIAL_ERROR = 30
SCORE_CMD_UNEXPECTED_EXIT = 15 # Base score, individual commands might override
SCORE_CMD_OUTPUT_MISMATCH = 15 # Base score
SCORE_CMD_EXECUTION_ERROR = 20
SCORE_CMD_NOT_FOUND = 15
SCORE_CMD_LOW_PROCESS_COUNT = 15
SCORE_CMD_PIPE_FAIL = 20      # Specific score for pipe failure
# Session Errors
SCORE_PROTOCOL_ERROR_SESSION = 30

# --- Score Interpretation Thresholds ---
THRESHOLDS = {
    (0, 10): "Very Likely Clear",
    (11, 30): "Low Suspicion",
    (31, 60): "Medium Suspicion (Possible Honeypot)",
    (61, 90): "High Suspicion (Likely Honeypot)",
    (91, float('inf')): "Very High Confidence Honeypot"
}

# --- Banner/Credential Config --- (Reduced lists for brevity in example)
BANNER_INDICATORS = ["honeypot", "cowrie", "kippo", "decoy"]
SSH_WEAK_CREDS = [("root", "root"), ("admin", "admin"), ("test", "test")]

# --- Enhanced Fidelity Commands ---
# Added more fields: 'expect_exact', 'expect_regex', 'min_lines', specific scores
FIDELITY_COMMANDS = [
    # Basic Checks
    {"cmd": "uname -a", "expect_substr": ["Linux", "BSD", "SunOS"], "score_fail": 10, "desc": "Check OS Kernel"},
    {"cmd": "id", "expect_substr": "uid=", "score_fail": 10, "desc": "Check User ID"},
    {"cmd": "env", "expect_substr": "PATH=", "score_fail": 15, "desc": "Check Environment Variables"},
    {"cmd": "pwd", "expect_substr": "/", "score_fail": 5, "desc": "Check PWD command"},
    {"cmd": "false; echo $?", "expect_exact": "1", "score_fail": 20, "desc": "Check Exit Status Variable"},

    # Filesystem Interaction
    {"cmd": "echo test_$$ > /tmp/.h_test && cat /tmp/.h_test && rm /tmp/.h_test", "expect_regex": r"test_\d+", "score_fail": 15, "desc": "Test tmp write/read w/ PID"}, # Use PID for uniqueness
    {"cmd": "ls /etc/passwd", "expect_substr": "/etc/passwd", "score_fail": 5, "desc": "Check /etc/passwd existence"},
    {"cmd": "ls /proc/cpuinfo", "expect_substr": "/proc/cpuinfo", "score_fail": 10, "desc": "Check /proc/cpuinfo existence"},
    {"cmd": "ls /dev/null", "expect_substr": "/dev/null", "score_fail": 10, "desc": "Check /dev/null"},

    # Process Interaction
    {"cmd": "ps aux", "expect_substr": "PID", "min_lines": 10, "score_fail": 10, "score_low_lines": SCORE_CMD_LOW_PROCESS_COUNT, "desc": "Check process list"},

    # Shell Features
    {"cmd": "ls /etc | wc -l", "expect_regex": r"^\s*\d+\s*$", "score_fail": SCORE_CMD_PIPE_FAIL, "desc": "Check Piping"}, # Expect a number
]

# Behavioral Analysis Parameters
TIMING_TEST_COMMAND = "pwd"
TIMING_REPETITIONS = 5
TIMING_STDDEV_THRESHOLD = 0.25 # Slightly lowered threshold
TIMING_MAX_AVG_THRESHOLD = 1.2 # Slightly lowered threshold
# ---------------------

# Configure logging for Paramiko to suppress verbose output unless needed
logging.getLogger("paramiko").setLevel(logging.WARNING)

def interpret_score(score):
    """Interprets the honeypot score based on defined thresholds."""
    for (low, high), label in THRESHOLDS.items():
        if low <= score <= high:
            return label
    return "Unknown Score Range" # Should not happen with float('inf')

def check_banner_and_protocol(target_ip, target_port):
    """
    Checks banner/protocol, returns score contribution and status ('ok', 'error', 'detected').
    """
    print(f"[*] Checking banner/protocol on {target_ip}:{target_port}...")
    score = 0
    reasons = []
    start_time = time.time()

    # 1. Basic Socket Banner Grab
    try:
        with socket.create_connection((target_ip, target_port), timeout=CONN_TIMEOUT) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            try:
                banner_bytes = sock.recv(1024)
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                if banner:
                    print(f"[DEBUG] Received banner:\n{banner}\n" + "-"*20)
                    for indicator in BANNER_INDICATORS:
                        if indicator.lower() in banner.lower():
                            reason = f"Keyword '{indicator}' found in banner"
                            print(f"[SUSPICIOUS] {reason}")
                            score += SCORE_BANNER_KEYWORD
                            reasons.append(reason)
                            # Consider this strong enough for early detection in banner check
                            return score, reasons, 'detected'

                    if len(banner) < 20 and ("welcome" in banner.lower() or "login" in banner.lower()):
                        reason = f"Suspiciously short/generic banner: '{banner}'"
                        print(f"[SUSPICIOUS] {reason}")
                        score += SCORE_BANNER_SUSPICIOUS_GENERIC
                        reasons.append(reason)
                else:
                    print("[INFO] No text banner received or banner empty.")

            except socket.timeout:
                 print(f"[WARN] Timeout receiving initial banner from {target_ip}:{target_port}.")
                 # Don't score timeout itself, but proceed cautiously
            except Exception as decode_err:
                print(f"[WARN] Could not decode banner: {decode_err}.")

    except socket.timeout:
        print(f"[WARN] Timeout connecting to {target_ip}:{target_port}.")
        return 0, ["Connection timeout"], 'error' # Return error status
    except ConnectionRefusedError:
         print(f"[INFO] Connection refused by {target_ip}:{target_port}.")
         return 0, ["Connection refused"], 'clear' # Not a honeypot on this port
    except Exception as e:
        print(f"[ERROR] Error during initial socket connect/recv: {e}")
        return 0, [f"Socket error: {e}"], 'error'

    # 2. Paramiko SSH Protocol Check (if applicable)
    if target_port in CHECK_INTERACTION_ON_PORTS:
        print("[INFO] Attempting Paramiko SSH connection for protocol version info...")
        transport = None
        try:
            transport = paramiko.Transport((target_ip, target_port))
            transport.connect(hostkey=None, username=None, password=None, timeout=SSH_TIMEOUT)
            server_banner = transport.remote_version
            transport.close()

            if server_banner:
                print(f"[DEBUG] Paramiko received SSH server version: {server_banner}")
                for indicator in BANNER_INDICATORS:
                     if indicator.lower() in server_banner.lower():
                        reason = f"Keyword '{indicator}' found in SSH version string"
                        print(f"[SUSPICIOUS] {reason}")
                        score += SCORE_BANNER_KEYWORD
                        reasons.append(reason)
                        # Don't return 'detected' here yet, let interaction confirm

                # Add specific version checks here if desired, adding SCORE_BANNER_SUSPICIOUS_VERSION
                if "dropbear" in server_banner.lower() and any(yr in server_banner for yr in ["2012", "2013", "2014", "2015", "2016", "2017"]):
                    reason = f"Suspiciously old Dropbear version: {server_banner}"
                    print(f"[SUSPICIOUS] {reason}")
                    score += SCORE_BANNER_SUSPICIOUS_VERSION
                    reasons.append(reason)

            else:
                 print("[WARN] Paramiko did not retrieve a clear SSH server version string.")

        except paramiko.SSHException as ssh_err:
             reason = f"Paramiko SSH protocol error during initial connection: {ssh_err}"
             print(f"[SUSPICIOUS] {reason}")
             score += SCORE_PROTOCOL_ERROR_INIT
             reasons.append(reason)
             # Consider protocol error strong enough for early exit
             if transport and transport.is_active(): transport.close()
             return score, reasons, 'detected'
        except socket.timeout:
            print(f"[WARN] Timeout during Paramiko SSH connection attempt.")
            # Don't add score, main connect already handled timeout. Might indicate slow honeypot.
        except Exception as e:
            print(f"[ERROR] Error during Paramiko SSH protocol check: {e}")
            if transport and transport.is_active(): transport.close()
            return score, [f"Paramiko connect error: {e}"], 'error' # Return existing score + error
        finally:
             if transport and transport.is_active(): transport.close()

    status = 'detected' if score >= THRESHOLDS[(11, 30)][0] else 'ok' # If score > 10, flag as potentially detected early
    return score, reasons, status


def perform_ssh_interaction(target_ip, target_port, initial_score=0):
    """
    Performs detailed SSH interaction and returns a cumulative honeypot score and reasons.
    Returns score, list_of_reasons, status ('ok', 'error', 'detected').
    """
    print(f"\n[*] Starting SSH Interaction & Behavioral Analysis on {target_ip}:{target_port}...")
    current_score = initial_score
    reasons = []
    overall_status = 'ok' # Default status unless error or detection occurs

    for username, password in SSH_WEAK_CREDS:
        print(f"\n[INFO] Trying SSH login: {username}:{password}...")
        ssh_client = None
        session_score = 0 # Score for this specific credential attempt
        session_reasons = []
        session_status = 'ok'

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_start_time = time.time()
            ssh_client.connect(
                hostname=target_ip, port=target_port, username=username, password=password,
                timeout=SSH_TIMEOUT, banner_timeout=SSH_TIMEOUT, auth_timeout=SSH_TIMEOUT,
                look_for_keys=False, allow_agent=False
            )
            connect_duration = time.time() - connect_start_time
            print(f"[DEBUG] SSH connection successful ({username}:{password}) took {connect_duration:.4f}s.")

            # <<< Score Point: Weak Login Success >>>
            reason = f"Successful SSH login with weak credentials: {username}:{password}"
            print(f"[SCORE +{SCORE_WEAK_LOGIN_SUCCESS}] {reason}")
            session_score += SCORE_WEAK_LOGIN_SUCCESS
            session_reasons.append(reason)
            session_status = 'detected' # Mark this session as suspicious

            # --- Behavioral Analysis: Command Timing ---
            print(f"[*] Performing command timing analysis ('{TIMING_TEST_COMMAND}' x{TIMING_REPETITIONS})...")
            response_times = []
            timing_errors = 0
            for i in range(TIMING_REPETITIONS):
                time.sleep(INTER_COMMAND_DELAY)
                cmd_start_time = time.time()
                try:
                    stdin, stdout, stderr = ssh_client.exec_command(TIMING_TEST_COMMAND, timeout=SSH_TIMEOUT)
                    exit_status = stdout.channel.recv_exit_status()
                    cmd_end_time = time.time()
                    if exit_status == 0:
                        response_times.append(cmd_end_time - cmd_start_time)
                    else:
                         print(f"[WARN] Timing command exit status {exit_status} on iteration {i+1}")
                         timing_errors += 1
                         session_score += SCORE_TIMING_ERROR
                         session_reasons.append(f"Timing command failed (iter {i+1}, exit {exit_status})")
                except Exception as timing_err:
                     print(f"[WARN] Error executing timing command on iter {i+1}: {timing_err}")
                     timing_errors += 1
                     session_score += SCORE_TIMING_ERROR
                     session_reasons.append(f"Timing command error (iter {i+1}): {timing_err}")
                     if timing_errors > TIMING_REPETITIONS // 2: break

            if len(response_times) >= 3:
                avg_time = statistics.mean(response_times)
                std_dev = statistics.stdev(response_times) if len(response_times) > 1 else 0
                print(f"[DEBUG] Timing results: Avg={avg_time:.4f}s, StdDev={std_dev:.4f}s, Times={response_times}")

                if std_dev > TIMING_STDDEV_THRESHOLD:
                     # Scale score based on how much threshold is exceeded
                     timing_score = SCORE_TIMING_HIGH_STDDEV_BASE + int(10 * (std_dev / TIMING_STDDEV_THRESHOLD - 1))
                     reason = f"High timing StdDev ({std_dev:.4f}s > {TIMING_STDDEV_THRESHOLD}s)"
                     print(f"[SCORE +{timing_score}] {reason}")
                     session_score += timing_score
                     session_reasons.append(reason)
                     session_status = 'detected'

                if avg_time > TIMING_MAX_AVG_THRESHOLD:
                    timing_score = SCORE_TIMING_HIGH_AVG_BASE + int(10 * (avg_time / TIMING_MAX_AVG_THRESHOLD - 1))
                    reason = f"High average response time ({avg_time:.4f}s > {TIMING_MAX_AVG_THRESHOLD}s)"
                    print(f"[SCORE +{timing_score}] {reason}")
                    session_score += timing_score
                    session_reasons.append(reason)
                    session_status = 'detected'

            # --- Interaction Analysis: Command Fidelity ---
            print(f"[*] Performing command fidelity checks...")
            fidelity_checks_passed = True # Track if any fidelity check fails

            for test in FIDELITY_COMMANDS:
                print(f"  - Executing ({test['desc']}): '{test['cmd']}'")
                time.sleep(INTER_COMMAND_DELAY)
                output, err_output, exit_status = "", "", -1
                cmd_failed = False
                failure_reason = ""
                score_increase = 0

                try:
                    stdin, stdout, stderr = ssh_client.exec_command(test['cmd'], timeout=SSH_TIMEOUT)
                    # Read streams *before* getting exit status
                    output_bytes = stdout.read()
                    err_bytes = stderr.read()
                    # Now get status
                    exit_status = stdout.channel.recv_exit_status()

                    output = output_bytes.decode('utf-8', errors='ignore').strip()
                    err_output = err_bytes.decode('utf-8', errors='ignore').strip()

                    print(f"[DEBUG]   Exit Status: {exit_status}")
                    if output and len(output) < 200: print(f"[DEBUG]   Stdout: {output[:200]}{'...' if len(output) > 200 else ''}")
                    elif output: print(f"[DEBUG]   Stdout: (received {len(output)} bytes)")
                    if err_output: print(f"[DEBUG]   Stderr: {err_output}")

                    # Check for "Command not found" first
                    if "command not found" in err_output.lower() or "not found" in output.lower():
                        cmd_failed = True
                        failure_reason = f"Command '{test['cmd']}' resulted in 'command not found'."
                        score_increase = SCORE_CMD_NOT_FOUND

                    # Check exit status (if not already caught by 'not found')
                    elif exit_status != 0 and not cmd_failed:
                        # Allow non-zero for specific cases if needed in future
                        if "No such file or directory" not in err_output:
                            cmd_failed = True
                            failure_reason = f"Command '{test['cmd']}' exited unexpectedly (status {exit_status})"
                            score_increase = test.get('score_fail', SCORE_CMD_UNEXPECTED_EXIT) # Use specific or default score

                    # Check expected output (if command didn't fail exit/not_found)
                    elif not cmd_failed:
                        match = False
                        if test.get('expect_substr'):
                            # Can be string or list of strings (match any)
                            subs = test['expect_substr']
                            if isinstance(subs, str): subs = [subs]
                            for s in subs:
                                if s.lower() in output.lower() or s.lower() in err_output.lower(): # Check both streams
                                    match = True
                                    break
                        elif test.get('expect_exact'):
                            if output == test['expect_exact']:
                                match = True
                        elif test.get('expect_regex'):
                            if re.search(test['expect_regex'], output):
                                match = True
                        else:
                             match = True # No output check defined for this command

                        if not match:
                             cmd_failed = True
                             failure_reason = f"Command '{test['cmd']}' output mismatch."
                             score_increase = test.get('score_fail', SCORE_CMD_OUTPUT_MISMATCH)

                    # Check minimum lines (e.g., for 'ps aux')
                    if test.get('min_lines') and not cmd_failed:
                         num_lines = len(output.splitlines())
                         print(f"[DEBUG]   '{test['cmd']}' line count: {num_lines}")
                         if num_lines < test['min_lines']:
                             cmd_failed = True # Consider it a failure type
                             failure_reason = f"Command '{test['cmd']}' output has too few lines ({num_lines} < {test['min_lines']})."
                             score_increase = test.get('score_low_lines', SCORE_CMD_LOW_PROCESS_COUNT)

                except Exception as cmd_err:
                    cmd_failed = True
                    failure_reason = f"Error executing command '{test['cmd']}': {cmd_err}."
                    score_increase = SCORE_CMD_EXECUTION_ERROR # High score for execution error

                # Apply score if a check failed
                if cmd_failed:
                    print(f"[SCORE +{score_increase}] {failure_reason}")
                    session_score += score_increase
                    session_reasons.append(failure_reason)
                    session_status = 'detected'
                    fidelity_checks_passed = False
                    # Option: break fidelity loop on first failure? Or continue gathering evidence?
                    # break # Uncomment to stop checking fidelity after first failure

            # End of fidelity checks loop

            if fidelity_checks_passed:
                print("[INFO] Core fidelity checks passed for this session.")

            # Close client for this session
            ssh_client.close()

            # Add session score to overall score for the port
            current_score += session_score
            reasons.extend(session_reasons)
            if session_status == 'detected':
                overall_status = 'detected' # Mark port as detected if any session was suspicious

            # !! Important: Since weak login is a strong indicator, we can stop trying other creds !!
            print(f"[INFO] Finished check for {username}:{password}. Score contribution: {session_score}")
            break # Exit the credential loop after the first successful login

        except paramiko.AuthenticationException:
            print(f"[INFO] Authentication failed for {username}:{password}. (Expected)")
            if ssh_client: ssh_client.close()
            continue # To next credential

        except paramiko.SSHException as ssh_err:
             reason = f"SSH protocol error for {username}:{password}: {ssh_err}"
             print(f"[SCORE +{SCORE_PROTOCOL_ERROR_SESSION}] {reason}")
             current_score += SCORE_PROTOCOL_ERROR_SESSION
             reasons.append(reason)
             overall_status = 'detected' # Treat protocol errors as detection
             if ssh_client: ssh_client.close()
             # Stop checking credentials on this port after a protocol error
             break
        except socket.timeout:
            print(f"[WARN] Timeout during SSH connection/auth for {username}:{password}.")
            # Don't add score, but could indicate honeypot delay tactic.
            if ssh_client: ssh_client.close()
            continue # Try next credential
        except Exception as e:
            print(f"[ERROR] Unexpected error during SSH attempt for {username}:{password}: {e}")
            reasons.append(f"Unexpected SSH error: {e}")
            overall_status = 'error' # Mark port check as errored
            if ssh_client: ssh_client.close()
            break # Stop checking credentials on this port after unexpected error
        finally:
             if ssh_client: ssh_client.close()

    # After trying all credentials (or breaking early)
    if overall_status == 'ok' and not reasons:
        print("[INFO] No successful weak SSH logins or suspicious behavior detected via interaction.")

    return current_score, reasons, overall_status


# --- Main Execution ---
if __name__ == '__main__':
    start_run_time = time.time()
    print("="*60)
    print(" Starting Probabilistic Honeypot Detection")
    print(f" Target IP:      {TARGET_IP}")
    print(f" Target Ports:   {TARGET_PORTS}")
    print(f" Interaction on: {CHECK_INTERACTION_ON_PORTS}")
    print("="*60)

    max_score = 0
    overall_reasons = []
    checked_ports_summary = {} # Store results per port

    for port in TARGET_PORTS:
        print(f"\n--- Checking Port {port} ---")
        port_score = 0
        port_reasons = []
        port_status = 'clear' # Default status

        # 1. Check Banner / Protocol
        banner_score, banner_reasons, banner_status = check_banner_and_protocol(TARGET_IP, port)
        port_score += banner_score
        port_reasons.extend(banner_reasons)

        if banner_status == 'error':
            print(f"[PORT {port} VERDICT] Inconclusive due to Banner/Protocol Check Error.")
            port_status = 'error'
            checked_ports_summary[port] = {'score': port_score, 'status': port_status, 'reasons': port_reasons}
            continue # Move to next port
        elif banner_status == 'detected':
             print(f"[PORT {port} INFO] Initial banner/protocol check raised suspicion (Score: {banner_score}).")
             port_status = 'suspicious'
        elif banner_status == 'clear':
            print(f"[PORT {port} INFO] Banner/protocol check appears clear (Score: {banner_score}).")
            # Continue if clear, but might be overridden by interaction checks

        # 2. Perform Interaction Check (if applicable)
        if port in CHECK_INTERACTION_ON_PORTS:
            interaction_score, interaction_reasons, interaction_status = perform_ssh_interaction(TARGET_IP, port, initial_score=port_score) # Pass banner score

            # Update port score and reasons ONLY with the interaction results
            # We use interaction_score directly as it included the initial score.
            port_score = interaction_score
            port_reasons = interaction_reasons # Replace banner reasons if interaction occurred

            if interaction_status == 'error':
                print(f"[PORT {port} VERDICT] Inconclusive due to Interaction Check Error.")
                port_status = 'error'
            elif interaction_status == 'detected':
                print(f"[PORT {port} VERDICT] Interaction/Behavior check raised suspicion (Final Score: {port_score}).")
                port_status = 'suspicious' # Or 'detected' based on threshold later
            else: # Interaction was 'ok'
                 if port_status != 'suspicious': # If banner wasn't already suspicious
                     print(f"[PORT {port} VERDICT] Interaction check appears clear (Final Score: {port_score}).")
                     port_status = 'clear'
                 else:
                      print(f"[PORT {port} VERDICT] Interaction clear, but banner/protocol was suspicious (Final Score: {port_score}).")
                      port_status = 'suspicious' # Keep suspicious status from banner

        else:
             # No interaction check performed, use banner status
             port_status = 'clear' if port_score == 0 else 'suspicious'
             print(f"[PORT {port} VERDICT] No interaction check performed (Final Score: {port_score}, Status: {port_status}).")


        # Store results and update max score
        checked_ports_summary[port] = {'score': port_score, 'status': port_status, 'reasons': port_reasons}
        if port_score > max_score:
            max_score = port_score
            overall_reasons = port_reasons # Use reasons from the highest scoring port

    # --- Final Summary ---
    run_duration = time.time() - start_run_time
    print("\n" + "="*60)
    print(f" Overall Honeypot Detection Summary (Completed in {run_duration:.2f}s)")
    print("="*60)

    if not checked_ports_summary:
        print("No ports were successfully checked.")
        sys.exit(0)

    print(f"Highest Score Detected: {max_score}")
    final_verdict = interpret_score(max_score)
    print(f"Overall Assessment: [{final_verdict}]")

    if max_score > 0:
        print("\nKey Indicators Contributing to Highest Score:")
        # Print only unique reasons, preserving order roughly
        unique_reasons = []
        for r in overall_reasons:
            if r not in unique_reasons:
                unique_reasons.append(r)
        for i, reason in enumerate(unique_reasons):
             print(f"  {i+1}. {reason}")

    # Recommend action based on verdict
    print("\nRecommended Action:")
    if max_score >= THRESHOLDS[(61, 90)][0]: # High suspicion or worse
        print("[!] Abort intended actions. Target is likely a honeypot.")
        print("="*60)
        sys.exit(1)
    elif max_score >= THRESHOLDS[(31, 60)][0]: # Medium suspicion
         print("[?] Proceed with extreme caution. Target exhibits suspicious behavior.")
    else: # Low suspicion or clear
        print("[+] Proceed, but remain vigilant. No strong honeypot indicators found.")

    print("\nSimulating proceeding based on assessment...")
    # --- Simulated Payload Execution ---
    time.sleep(1)
    print("[PAYLOAD] ...performing actions on target...")
    time.sleep(1)
    print("[PAYLOAD] Finished.")
    # --- End Simulated Payload ---
    print("="*60)
