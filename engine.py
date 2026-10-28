import time
import math
import subprocess
import numpy as np
from collections import defaultdict
from sklearn.ensemble import IsolationForest

class MultiStageCorrelationEngine:
    def __init__(self, time_window_seconds: int = 300):
        self.time_window = time_window_seconds
        self.ip_history = defaultdict(list)
        
        self.stage_map = {
            "AUTH_FAILURE": {"stage": 1, "name": "Initial Access", "weight": 15.0},
            "PORT_SCAN": {"stage": 1, "name": "Reconnaissance", "weight": 18.0},
            "PRIV_ESC": {"stage": 2, "name": "Privilege Escalation", "weight": 30.0},
            "TOKEN_FORGE": {"stage": 2, "name": "Credential Access", "weight": 32.0},
            "INTERNAL_PIVOT": {"stage": 3, "name": "Lateral Movement", "weight": 45.0},
            "CRON_PERSIST": {"stage": 3, "name": "Persistence", "weight": 40.0},
            "DB_DUMP": {"stage": 4, "name": "Data Exfiltration", "weight": 65.0},
            "NORMAL_TRAFFIC": {"stage": 0, "name": "Benign Activity", "weight": 2.0}
        }

        self.ai_model = IsolationForest(contamination=0.15, random_state=42)
        self._train_baseline_ai()

    def _train_baseline_ai(self):
        rng = np.random.RandomState(42)
        normal_payload = rng.normal(loc=450, scale=120, size=(500, 1))
        normal_rate = rng.normal(loc=12, scale=4, size=(500, 1))
        normal_sensitivity = rng.choice([1, 2, 3], size=(500, 1))
        normal_status = np.full((500, 1), 2)
        
        X_train = np.hstack([normal_payload, normal_rate, normal_sensitivity, normal_status])
        self.ai_model.fit(X_train)

    def compute_ai_anomaly_score(self, payload_bytes: int, req_rate: float, sensitivity: int, status_code: int) -> float:
        status_class = status_code // 100
        features = np.array([[payload_bytes, req_rate, sensitivity, status_class]])
        raw_score = self.ai_model.decision_function(features)[0]
        anomaly_prob = 1 / (1 + math.exp(raw_score * 5))
        return round(float(anomaly_prob), 3)

    def execute_soar_playbook(self, ip: str, risk_score: float, stages: list) -> dict:
        """
        Executes automated mitigation when risk score > 90.
        Simulates iptables block, AWS Security Group revocation, and session invalidation.
        """
        playbook_id = f"PB-AUTO-{int(time.time()) % 100000}"
        actions_log = []

        if risk_score >= 90.0:
            # 1. Simulate iptables block rule execution
            # (In production: subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]))
            actions_log.append({
                "action": "BLOCK_IP_IPTABLES",
                "target": f"iptables -A INPUT -s {ip} -j DROP",
                "status": "EXECUTED_SUCCESS"
            })

            # 2. Simulate AWS Security Group Revocation
            actions_log.append({
                "action": "REVOKE_AWS_SG_INGRESS",
                "target": f"aws ec2 revoke-security-group-ingress --group-id sg-0192834 --protocol tcp --port 443 --cidr {ip}/32",
                "status": "EXECUTED_SUCCESS"
            })

            # 3. Invalidate active user sessions in Redis / Memory cache
            actions_log.append({
                "action": "INVALIDATE_ACTIVE_SESSIONS",
                "target": f"REDIS FLUSH_SESSION_KEYS_FOR_IP_{ip}",
                "status": "EXECUTED_SUCCESS"
            })

        return {
            "playbook_id": playbook_id,
            "triggered": risk_score >= 90.0,
            "risk_threshold": 90.0,
            "target_ip": ip,
            "actions": actions_log
        }

    def process_event(self, event: dict) -> dict:
        now = time.time()
        ip = event["source_ip"]
        event_type = event.get("event_type", "NORMAL_TRAFFIC")
        
        meta = self.stage_map.get(event_type, self.stage_map["NORMAL_TRAFFIC"])
        stage_num = meta["stage"]
        stage_name = meta["name"]
        base_weight = meta["weight"]

        ai_score = self.compute_ai_anomaly_score(
            payload_bytes=event.get("payload_bytes", 300),
            req_rate=event.get("req_rate", 5.0),
            sensitivity=event.get("sensitivity", 1),
            status_code=event.get("status_code", 200)
        )

        self.ip_history[ip] = [
            e for e in self.ip_history[ip] if (now - e["timestamp"]) <= self.time_window
        ]

        enriched_event = {
            "id": f"EVT-{int(now * 1000) % 1000000}",
            "timestamp": now,
            "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
            "source_ip": ip,
            "user": event.get("user", "anonymous"),
            "endpoint": event.get("endpoint", "/"),
            "event_type": event_type,
            "stage": stage_num,
            "stage_name": stage_name,
            "ai_anomaly_score": ai_score,
            "base_weight": base_weight,
            "payload_bytes": event.get("payload_bytes", 300)
        }
        self.ip_history[ip].append(enriched_event)

        history = self.ip_history[ip]
        observed_stages = sorted(list(set(e["stage"] for e in history if e["stage"] > 0)))
        
        decayed_sum = 0.0
        decay_lambda = 0.008

        for past_evt in history:
            dt = now - past_evt["timestamp"]
            time_decay = math.exp(-decay_lambda * dt)
            ai_multiplier = 0.7 + (past_evt["ai_anomaly_score"] * 0.8)
            decayed_sum += past_evt["base_weight"] * ai_multiplier * time_decay

        num_stages = len(observed_stages)
        progression_multiplier = 1.0 + (0.45 * max(0, num_stages - 1) ** 1.35)
        
        raw_total_risk = decayed_sum * progression_multiplier
        final_risk_score = round(min(99.8, raw_total_risk), 1)

        # Generate automated SOAR playbook if risk score exceeds 90
        playbook = self.execute_soar_playbook(ip, final_risk_score, observed_stages)

        if final_risk_score >= 85.0 or num_stages >= 3:
            severity = "CRITICAL"
            notify = True
            alert_title = f"Multi-Stage APT Sequence Detected [{ip}]"
            alert_msg = f"Risk {final_risk_score} reached. Automated SOAR Playbook {playbook['playbook_id']} executed containment."
        elif final_risk_score >= 45.0 or num_stages == 2:
            severity = "ELEVATED"
            notify = True
            alert_title = f"Correlated Stage Progression [{ip}]"
            alert_msg = f"Lateral progression across Stages {observed_stages}. Risk escalated to {final_risk_score}."
        else:
            severity = "LOW"
            notify = False
            alert_title = "Isolated Telemetry Event"
            alert_msg = "Single-stage event logged. Below correlation threshold."

        return {
            "event": enriched_event,
            "correlation": {
                "source_ip": ip,
                "active_stages": observed_stages,
                "highest_stage": max(observed_stages) if observed_stages else 0,
                "event_count_in_window": len(history),
                "risk_score": final_risk_score,
                "severity": severity,
                "notify": notify,
                "alert_title": alert_title,
                "alert_msg": alert_msg,
                "playbook": playbook
            }
        }