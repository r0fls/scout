import time
from scout.Monitor import Monitor

RUN_PERIOD = 10

def run():
    monitor = Monitor()
    while True:
        monitor.run_monitor()
        time.sleep(RUN_PERIOD)
