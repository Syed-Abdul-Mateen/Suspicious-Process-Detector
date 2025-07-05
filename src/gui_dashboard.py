import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import time
import json
import os
from detector import is_suspicious
import psutil

CONFIG_PATH = "config/rules.json"
LOG_PATH = "logs/suspicious_log.txt"

class DetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Suspicious Process Activity Detector")
        self.root.geometry("1000x650")
        self.root.configure(bg="#1e1e1e")

        self.running = False
        self.thread = None

        self.load_rules()

        self.build_header()
        self.build_toggles()
        self.build_controls()
        self.build_log_viewer()

        self.refresh_log()

    def load_rules(self):
        with open(CONFIG_PATH, "r") as f:
            self.rules = json.load(f)

    def save_rules(self):
        with open(CONFIG_PATH, "w") as f:
            json.dump(self.rules, f, indent=2)

    def build_header(self):
        title = tk.Label(
            self.root, text="Suspicious Process Activity Detector",
            font=("Segoe UI", 18, "bold"), bg="#1e1e1e", fg="#4FC3F7"
        )
        title.pack(pady=10)

    def build_toggles(self):
        self.toggle_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.toggle_frame.pack(pady=10)

        self.vars = {
            "cpu": tk.BooleanVar(value=True),
            "memory": tk.BooleanVar(value=True),
            "path": tk.BooleanVar(value=True),
            "parent_child": tk.BooleanVar(value=True),
            "blacklist": tk.BooleanVar(value=True)
        }

        row = 0
        for key, var in self.vars.items():
            label = tk.Label(self.toggle_frame, text=key.replace("_", " ").title(),
                             bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 11))
            label.grid(row=row, column=0, sticky="w", padx=5, pady=4)

            toggle = ttk.Checkbutton(
                self.toggle_frame, variable=var, command=self.update_rules
            )
            toggle.grid(row=row, column=1, padx=10)
            row += 1

    def update_rules(self):
        self.rules["enable_cpu_check"] = self.vars["cpu"].get()
        self.rules["enable_memory_check"] = self.vars["memory"].get()
        self.rules["enable_path_check"] = self.vars["path"].get()
        self.rules["enable_parent_child_check"] = self.vars["parent_child"].get()
        self.rules["enable_blacklist_check"] = self.vars["blacklist"].get()
        self.save_rules()

    def build_controls(self):
        self.control_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.control_frame.pack(pady=10)

        self.start_btn = tk.Button(
            self.control_frame, text="Start Monitoring", bg="#388E3C", fg="#ffffff",
            font=("Segoe UI", 10, "bold"), width=20, command=self.toggle_monitoring
        )
        self.start_btn.grid(row=0, column=0, padx=5)

        self.stop_btn = tk.Button(
            self.control_frame, text="Stop", bg="#D32F2F", fg="#ffffff",
            font=("Segoe UI", 10, "bold"), width=20, command=self.stop_monitoring, state=tk.DISABLED
        )
        self.stop_btn.grid(row=0, column=1, padx=5)

    def build_log_viewer(self):
        label = tk.Label(self.root, text="Live Log Viewer", bg="#1e1e1e", fg="#FFEB3B",
                         font=("Segoe UI", 13, "bold"))
        label.pack()

        self.log_box = ScrolledText(self.root, height=20, width=120, bg="#2b2b2b",
                                    fg="#f1f1f1", insertbackground="#f1f1f1", font=("Consolas", 10))
        self.log_box.pack(padx=20, pady=10)
        self.log_box.configure(state=tk.DISABLED)

    def refresh_log(self):
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                content = f.read()
            self.log_box.configure(state=tk.NORMAL)
            self.log_box.delete(1.0, tk.END)
            self.log_box.insert(tk.END, content)
            self.log_box.configure(state=tk.DISABLED)
        except Exception as e:
            pass

        self.root.after(3000, self.refresh_log)

    def monitor_loop(self):
        while self.running:
            for proc in psutil.process_iter():
                is_suspicious(proc)
            time.sleep(2)

    def toggle_monitoring(self):
        self.running = True
        self.thread = threading.Thread(target=self.monitor_loop)
        self.thread.daemon = True
        self.thread.start()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

    def stop_monitoring(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = DetectorGUI(root)
    root.mainloop()
