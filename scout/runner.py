import time
import argparse

from scout.Monitor import Monitor


def run():
    parser = argparse.ArgumentParser(description="Monitor your W3C formatted HTTP access log.  See:\nhttp://www.w3.org/Daemon/User/Config/Logging.html")
    parser.add_argument("file",
                        help="The http access log file you want to monitor")
    parser.add_argument("--format", default="common",
                        help="The format of your access log")
    parser.add_argument("--period", type=int, default=10,
                        help="How often (in seconds) scout will display monitoring statistics")
    parser.add_argument("--alert-period", type=int, default=2,
                        help="How long (in minutes) the high traffic alert period will last.")
    parser.add_argument("--alert-threshold", type=int, default=10,
                        help="The number of requests in the alert period that will trigger a high traffic warning.")
    parser.add_argument("--max-frequent-sections", type=int, default=10,
                        help="The maximum number of most-frequently-requested sections to show.")

    args = parser.parse_args()
    monitor = Monitor(args.file, args.format, args.period, args.alert_period, args.alert_threshold, args.max_frequent_sections)
    while True:
        monitor.run_monitor()
        time.sleep(args.period)
