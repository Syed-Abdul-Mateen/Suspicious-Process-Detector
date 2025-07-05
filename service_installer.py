# service_installer.py

import win32serviceutil
import win32service
import win32event
import subprocess
import os
import sys

class SuspiciousProcessDetectorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SuspiciousProcessDetector"
    _svc_display_name_ = "Suspicious Process Activity Detector"
    _svc_description_ = "Monitors and blocks suspicious processes in real-time."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        main_script = os.path.join(dir_path, 'src', 'main.py')

        while self.running:
            try:
                # Run the Python script silently
                proc = subprocess.Popen(
                    ['pythonw.exe', main_script],
                    cwd=dir_path,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                proc.wait()
            except Exception as e:
                print(f"[ERROR] Service failed: {e}")
                import time
                time.sleep(5)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Run as service
        win32serviceutil.HandleCommandLine(SuspiciousProcessDetectorService)
    else:
        # Handle other commands like install/start/stop
        win32serviceutil.HandleCommandLine(SuspiciousProcessDetectorService)