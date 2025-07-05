# Suspicious Process Detector

## Overview

The Suspicious Process Detector is a Python-based tool for monitoring and identifying potentially malicious or unauthorized processes running on a Windows system. It uses a combination of rule-based detection, resource monitoring, and anomaly analysis to flag suspicious activity in real-time. When a suspicious process is detected, the tool logs the event, sends a desktop notification, and can be configured to automatically terminate the process.

## Features

-   **Real-time Monitoring:** Continuously scans running processes to detect threats as they emerge.
-   **Multi-faceted Detection:**
    -   **Process Blacklisting:** Identifies and terminates known malicious processes based on a configurable blacklist.
    -   **Suspicious Path Detection:** Flags processes running from unusual or temporary locations (e.g., `C:\Windows\Temp`).
    -   **Resource Monitoring:** Alerts on processes exhibiting unusually high CPU or memory usage.
    -   **Parent-Child Anomaly Detection:** Detects suspicious parent-child process relationships (e.g., `powershell.exe` spawning an unexpected application).
    -   **Network Activity Monitoring:** Flags processes that establish network connections, which can be an indicator of unauthorized communication.
-   **Configurable Rules:** All detection parameters can be easily customized through a central `rules.json` file without modifying the source code.
-   **Logging and Reporting:**
    -   Maintains a detailed log of all suspicious activities in `logs/suspicious_log.txt`.
    -   Generates a comprehensive PDF summary report of all findings upon termination.
-   **Automated Response:** Can automatically kill blacklisted processes upon detection.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Syed-Abdul-Mateen/SuspiciousProcessDetector.git
    cd SuspiciousProcessDetector
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    venv\Scripts\activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To start the detector, run the `main.py` script from the project's root directory:

```bash
python src/main.py
```

The tool will start monitoring processes in the background. All suspicious activities will be logged to `logs/suspicious_log.txt` and displayed in the console.

To stop the monitor, press `Ctrl+C`. A PDF report named `suspicious_report_YYYYMMDD_HHMMSS.pdf` will be generated in the `reports` directory.

## Configuration Customization

The detection logic is controlled by the `src/config/rules.json` file. You can modify this file to tailor the detector to your needs.

-   `blacklist`: A list of process names (e.g., `"malware.exe"`) to automatically terminate.
-   `suspicious_paths`: A list of directory paths where processes should not typically run from.
-   `cpu_threshold`: The CPU usage percentage above which a process is considered suspicious.
-   `memory_threshold`: The memory usage (in MB) above which a process is considered suspicious.
-   `parent_child_rules`: Defines rules for parent-child anomaly detection.
    -   `suspicious_parents`: A list of parent processes that are monitored.
    -   `allowed_children`: A dictionary mapping a parent process to a list of its legitimate child processes.
-   `enable_*_check`: Set these boolean flags (`true` or `false`) to toggle specific detection features on or off.
