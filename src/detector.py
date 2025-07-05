import psutil
import os
import json
import logging
from datetime import datetime
from win10toast import ToastNotifier

# --- Log directory creation to prevent EXE crash ---
log_dir = os.path.join(os.getenv('LOCALAPPDATA'), 'Temp', 'logs')
os.makedirs(log_dir, exist_ok=True)
LOG_PATH = os.path.join(log_dir, 'suspicious_log.txt')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Add file handler to log to the actual log file
file_handler = logging.FileHandler(LOG_PATH)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(file_handler)

# Config file path
import sys

if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(__file__)

CONFIG_PATH = os.path.join(base_path, 'config', 'rules.json')


class Detector:
    def __init__(self):
        self.rules = self._load_rules()
        self.notifier = ToastNotifier()
        self.logged_pids = set()  # Track PIDs to avoid duplicate alerts

    def _load_rules(self):
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logging.error(f"Configuration file not found at {CONFIG_PATH}")
            return {}
        except json.JSONDecodeError:
            logging.error(f"Error decoding JSON from {CONFIG_PATH}")
            return {}

    def log_and_notify(self, process_info, reason):
        pid = process_info.get('pid')
        if pid in self.logged_pids:
            return  # Avoid duplicate alerts

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"[{now}] {reason} | "
            f"PID: {process_info.get('pid', 'N/A')} | "
            f"Name: {process_info.get('name', 'N/A')} | "
            f"Path: {process_info.get('exe', 'N/A')} | "
            f"CPU: {process_info.get('cpu', 0):.2f}% | "
            f"Memory: {process_info.get('mem', 0):.2f}MB | "
            f"Parent: {process_info.get('parent', 'N/A')}"
        )

        logging.warning(log_entry)
        self.notifier.show_toast(
            "Suspicious Process Detected!",
            log_entry,
            duration=10,
            threaded=True
        )
        if pid:
            self.logged_pids.add(pid)

    def check_process(self, proc):
        try:
            if not proc.is_running():
                return

            pid = proc.pid

            if pid in self.logged_pids and not psutil.pid_exists(pid):
                self.logged_pids.remove(pid)
                return

            name = proc.name()
            exe = ""
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, FileNotFoundError):
                exe = "Access Denied"

            process_info = {
                "pid": pid,
                "name": name,
                "exe": exe,
                "cpu": proc.cpu_percent(interval=0.01),
                "mem": proc.memory_info().rss / (1024 * 1024),
                "parent": "N/A"
            }

            try:
                parent = proc.parent()
                if parent:
                    process_info["parent"] = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            self._check_blacklist(proc, process_info)
            self._check_path(process_info)
            self._check_resource_usage(process_info)
            self._check_parent_child_anomaly(process_info)
            self._check_network(proc, process_info)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logging.error(f"Error analyzing process PID {proc.pid if 'proc' in locals() else 'N/A'}: {e}")

    def _check_blacklist(self, proc, process_info):
        if self.rules.get("enable_blacklist_check"):
            name = process_info["name"]
            blacklist = self.rules.get("blacklist", [])
            if name in blacklist:
                self.log_and_notify(process_info, f"Blacklisted process: {name}")
                try:
                    proc.kill()
                    logging.info(f"KILLED process {name} (PID {process_info['pid']})")
                except Exception as e:
                    logging.error(f"Failed to kill process {name}: {e}")

    def _check_path(self, process_info):
        if self.rules.get("enable_path_check") and process_info["exe"] != "Access Denied":
            suspicious_paths = self.rules.get("suspicious_paths", [])
            for path in suspicious_paths:
                if process_info["exe"].startswith(path):
                    self.log_and_notify(process_info, f"Suspicious path: {process_info['exe']}")
                    break

    def _check_resource_usage(self, process_info):
        if self.rules.get("enable_cpu_check") and process_info["cpu"] > self.rules.get("cpu_threshold", 80):
            self.log_and_notify(process_info, f"High CPU usage: {process_info['cpu']:.2f}%")
        if self.rules.get("enable_memory_check") and process_info["mem"] > self.rules.get("memory_threshold", 500):
            self.log_and_notify(process_info, f"High Memory usage: {process_info['mem']:.2f}MB")

    def _check_parent_child_anomaly(self, process_info):
        if self.rules.get("enable_parent_child_check"):
            parent_name = process_info["parent"]
            child_name = process_info["name"]
            rules = self.rules.get("parent_child_rules", {})

            if parent_name in rules.get("suspicious_parents", []) and \
                    child_name not in rules.get("allowed_children", {}).get(parent_name, []):
                self.log_and_notify(process_info, f"Parent-child anomaly: {parent_name} -> {child_name}")

    def _check_network(self, proc, process_info):
        if self.rules.get("enable_network_check"):
            try:
                connections = proc.connections(kind='inet')
                if connections:
                    self.log_and_notify(process_info, f"Process has active network connections")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
