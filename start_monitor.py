# project/start_monitor.py
from network_traffic_monitor import NetworkTrafficMonitor

def main():
    monitor = NetworkTrafficMonitor(interface="eth0", max_packets=2000)
    monitor.start_monitoring(display_interval=10)

if __name__ == "__main__":
    main()
