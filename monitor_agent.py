import subprocess
import time
import joblib
import pandas as pd
from datetime import datetime

VICTIM = "labuser@192.168.50.102"
LOG_PATH = "~/nettool/logs.txt"

MODEL_PATH = "model.pkl"
POLL_INTERVAL = 5

# Load AI model
model = joblib.load(MODEL_PATH)

# Keep track of handled events
seen_lines = set()
blocked_ips = set()

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def fetch_logs():
    cmd = f"ssh {VICTIM} 'tail -n 100 {LOG_PATH}'"
    output = subprocess.getoutput(cmd)
    return output.split("\n")

def extract_ip(line):
    try:
        return line.split("|")[1].strip()
    except:
        return None

def extract_features(line):
    return pd.DataFrame([{
        "has_semicolon": int(";" in line),
        "has_and": int("&&" in line),
        "has_nc": int("nc" in line),
        "has_bash": int("bash" in line),
        "length": len(line)
    }])

def is_suspicious_rule(line):
    return any(x in line for x in [";", "&&", "nc", "bash"])

def ai_detect(features):
    return model.predict(features)[0]  # -1 = anomaly

def kill_malicious():
    subprocess.run(f"ssh {VICTIM} 'sudo pkill -f nc'", shell=True)
    subprocess.run(f"ssh {VICTIM} 'sudo pkill -f bash'", shell=True)

def block_ip(ip):
    if ip in blocked_ips:
        return

    log(f"[RESPONSE] Blocking {ip}")

    subprocess.run(
        f"ssh {VICTIM} 'sudo iptables -I INPUT 1 -s {ip} -j DROP'",
        shell=True
    )

    subprocess.run(
        f"ssh {VICTIM} 'sudo iptables -I OUTPUT 1 -d {ip} -j DROP'",
        shell=True
    )

    blocked_ips.add(ip)

def process_line(line):
    if not line or line in seen_lines:
        return

    seen_lines.add(line)

    ip = extract_ip(line)
    if not ip:
        return

    features = extract_features(line)
    ai_result = ai_detect(features)
    rule_trigger = is_suspicious_rule(line)

    if rule_trigger:
        log(f"[RULE] Suspicious pattern from {ip}")

    if ai_result == -1:
        log(f"[AI] Anomaly detected from {ip}")

    # 🔥 COMBINED DECISION
    if rule_trigger and ai_result == -1:
        log(f"[ALERT] Confirmed attack from {ip}")
        log(f"Line: {line}")

        kill_malicious()
        block_ip(ip)

def main():
    log("AI Monitoring Agent Started")

    while True:
        try:
            logs = fetch_logs()

            for line in logs:
                process_line(line)

        except Exception as e:
            log(f"[ERROR] {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
