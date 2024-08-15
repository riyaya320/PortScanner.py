import socket
import threading

class AdvancedPortScannerCLI:
    def __init__(self):
        self.ip = None
        self.port_start = None
        self.port_end = None
        self.timeout = None
        self.scan_type = None
        self.open_ports = []
        self.filtered_ports = []

    def get_input(self):
        try:
            self.ip = input("Enter the target IP address: ").strip()
            if not self.ip:
                raise ValueError("IP address cannot be empty.")
            
            port_range = input("Enter the port range (start-end): ").strip()
            if '-' not in port_range:
                raise ValueError("Port range must be in the format 'start-end'.")
            self.port_start, self.port_end = map(int, port_range.split('-'))

            self.timeout = float(input("Enter the timeout for each port scan (seconds): ").strip())
            if self.timeout <= 0:
                raise ValueError("Timeout must be a positive number.")
            
            print("Choose the scan type:")
            print("1. TCP Connect Scan")
            print("2. SYN Scan")
            print("3. UDP Scan")
            print("4. ACK Scan")
            scan_choice = int(input("Enter the number corresponding to the scan type: ").strip())
            scan_type_map = {
                1: "TCP Connect Scan",
                2: "SYN Scan",
                3: "UDP Scan",
                4: "ACK Scan"
            }
            self.scan_type = scan_type_map.get(scan_choice)
            if not self.scan_type:
                raise ValueError("Invalid scan type choice.")
        except ValueError as e:
            print(f"Input Error: {e}")
            self.get_input()

    def scan_ports(self):
        scan_func_map = {
            "TCP Connect Scan": self.scan_tcp_connect,
            "SYN Scan": self.scan_syn,
            "UDP Scan": self.scan_udp,
            "ACK Scan": self.scan_ack
        }

        scan_func = scan_func_map.get(self.scan_type)
        if not scan_func:
            print(f"Invalid scan type: {self.scan_type}")
            return

        threads = []
        for port in range(self.port_start, self.port_end + 1):
            t = threading.Thread(target=scan_func, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.print_results()

    def scan_tcp_connect(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            if result == 0:
                print(f"Port {port}/TCP is open.")
                self.open_ports.append(port)
            else:
                print(f"Port {port}/TCP is closed.")

    def scan_syn(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect_ex((self.ip, port))
            try:
                sock.send(b'\x02')  # SYN flag
                data = sock.recv(1024)
                if data:
                    print(f"Port {port}/TCP is open (SYN).")
                    self.open_ports.append(port)
                else:
                    print(f"Port {port}/TCP is closed (SYN).")
            except:
                print(f"Port {port}/TCP is closed (SYN).")

    def scan_udp(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.sendto(b"", (self.ip, port))
                sock.recvfrom(1024)
                print(f"Port {port}/UDP is open.")
                self.open_ports.append(port)
            except socket.timeout:
                print(f"Port {port}/UDP is open/filtered.")
                self.filtered_ports.append(port)
            except:
                print(f"Port {port}/UDP is closed.")

    def scan_ack(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect_ex((self.ip, port))
            try:
                sock.send(b'\x10')  # ACK flag
                data = sock.recv(1024)
                if data:
                    print(f"Port {port}/TCP is unfiltered (ACK).")
                else:
                    print(f"Port {port}/TCP is filtered (ACK).")
            except:
                print(f"Port {port}/TCP is filtered (ACK).")

    def print_results(self):
        open_ports_str = ', '.join(map(str, self.open_ports)) if self.open_ports else "None"
        filtered_ports_str = ', '.join(map(str, self.filtered_ports)) if self.filtered_ports else "None"
        print(f"\nScan complete.\nOpen ports: {open_ports_str}\nFiltered ports: {filtered_ports_str}")

if __name__ == "__main__":
    scanner = AdvancedPortScannerCLI()
    scanner.get_input()
    scanner.scan_ports()
