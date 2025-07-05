import time
import psutil
import logging
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector import Detector
from report_generator import create_pdf_report

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def monitor():
    logging.info("Starting Suspicious Process Activity Detector...")
    detector = Detector()
    
    try:
        while True:
            # Fetch the process list once
            procs = {p.pid: p for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'exe', 'ppid'])}
            
            for pid, proc in procs.items():
                detector.check_process(proc)
            
            # Reduce sleep time for more responsive monitoring
            time.sleep(1)
            
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")
    except Exception as e:
        logging.critical(f"A critical error occurred in the monitor loop: {e}")

if __name__ == "__main__":
    try:
        monitor()
    finally:
        logging.info("Generating final report...")
        create_pdf_report()
        logging.info("Report generation complete. Exiting.")
