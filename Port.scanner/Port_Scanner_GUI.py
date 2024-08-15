import tkinter as tk
from tkinter import messagebox, filedialog
import socket
import threading
import time
import unittest

class AdvancedPortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Port Scanner")
        self.root.geometry("800x700")
        self.root.configure(bg="black")
        
        # Create Frames
        self.frame1 = tk.Frame(self.root, bg="black")
        self.frame2 = tk.Frame(self.root, bg="black")

        # Initialize frame1
        self.create_frame1()
        
        # Initialize frame2 with scanner features
        self.create_frame2()

    def create_frame1(self):
        # Title Label
        title_label = tk.Label(self.frame1, text="Port Scanner", font=("Arial Black", 28), bg="white", fg="red")
        title_label.pack(pady=100)

        # Start Button
        start_button = tk.Button(self.frame1, text="Start", font=("Helvetica", 16), bg="Red", fg="white", command=self.show_frame2)
        start_button.pack(pady=20)

        self.frame1.pack(fill="both", expand=True)

    def create_frame2(self):
        self.ip_label = tk.Label(self.frame2, text="Target IP Address:", bg="#2c3e50", fg="white")
        self.ip_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.ip_entry = tk.Entry(self.frame2, width=30)
        self.ip_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.port_label = tk.Label(self.frame2, text="Port Range (start-end):", bg="#2c3e50", fg="white")
        self.port_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.port_entry = tk.Entry(self.frame2, width=30)
        self.port_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        self.timeout_label = tk.Label(self.frame2, text="Timeout (seconds):", bg="#2c3e50", fg="white")
        self.timeout_label.grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.timeout_entry = tk.Entry(self.frame2, width=30)
        self.timeout_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        self.timeout_entry.insert(0, "0.5")

        self.scan_type_label = tk.Label(self.frame2, text="Scan Type:", bg="#2c3e50", fg="white")
        self.scan_type_label.grid(row=3, column=0, padx=10, pady=10, sticky="e")
        self.scan_type = tk.StringVar(value="TCP Connect Scan")
        self.scan_type_menu = tk.OptionMenu(self.frame2, self.scan_type, "TCP Connect Scan", "SYN Scan", "UDP Scan", "ACK Scan")
        self.scan_type_menu.grid(row=3, column=1, padx=10, pady=10, sticky="w")

        self.scan_button = tk.Button(self.frame2, text="Scan", command=self.start_scan, bg="Red", fg="white")
        self.scan_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.result_text = tk.Text(self.frame2, width=90, height=20, bg="#ecf0f1", fg="black", wrap=tk.WORD)
        self.result_text.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        self.save_button = tk.Button(self.frame2, text="Save Results", command=self.save_results, bg="Red", fg="white")
        self.save_button.grid(row=6, column=0, columnspan=2, pady=10)

        self.clear_button = tk.Button(self.frame2, text="Clear", command=self.clear_results, bg="Red", fg="white")
        self.clear_button.grid(row=7, column=0, columnspan=2, pady=10)

    def show_frame2(self):
        self.frame1.pack_forget()
        self.frame2.pack(fill="both", expand=True)

    def start_scan(self):
        target_ip = self.ip_entry.get().strip()
        port_range = self.port_entry.get().strip()
        timeout = self.timeout_entry.get().strip()

        if not target_ip:
            messagebox.showerror("Error", "Please enter a valid IP address.")
            return

        if not port_range or '-' not in port_range:
            messagebox.showerror("Error", "Please enter a valid port range (start-end).")
            return

        try:
            port_start, port_end = map(int, port_range.split('-'))
        except ValueError:
            messagebox.showerror("Error", "Port range must be two integers separated by a hyphen.")
            return

        try:
            timeout = float(timeout)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid timeout value.")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning {target_ip} from port {port_start} to {port_end} using {self.scan_type.get()}...\n")

        scan_thread = threading.Thread(target=self.scan_ports, args=(target_ip, port_start, port_end, timeout))
        scan_thread.start()

    def scan_ports(self, ip, start_port, end_port, timeout):
        scan_type = self.scan_type.get()
        open_ports = []
        filtered_ports = []

        def scan_tcp_connect(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.update_result(f"Port {port}/TCP is open.\n", "open")
                    open_ports.append(port)
                else:
                    self.update_result(f"Port {port}/TCP is closed.\n", "closed")

        def scan_syn(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect_ex((ip, port))
                try:
                    sock.send(b'\x02')  # SYN flag
                    data = sock.recv(1024)
                    if data:
                        self.update_result(f"Port {port}/TCP is open (SYN).\n", "open")
                        open_ports.append(port)
                    else:
                        self.update_result(f"Port {port}/TCP is closed (SYN).\n", "closed")
                except:
                    self.update_result(f"Port {port}/TCP is closed (SYN).\n", "closed")

        def scan_udp(port):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                try:
                    sock.sendto(b"", (ip, port))
                    sock.recvfrom(1024)
                    self.update_result(f"Port {port}/UDP is open.\n", "open")
                    open_ports.append(port)
                except socket.timeout:
                    self.update_result(f"Port {port}/UDP is open/filtered.\n", "filtered")
                    filtered_ports.append(port)
                except:
                    self.update_result(f"Port {port}/UDP is closed.\n", "closed")

        def scan_ack(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect_ex((ip, port))
                try:
                    sock.send(b'\x10')  # ACK flag
                    data = sock.recv(1024)
                    if data:
                        self.update_result(f"Port {port}/TCP is unfiltered (ACK).\n", "unfiltered")
                    else:
                        self.update_result(f"Port {port}/TCP is filtered (ACK).\n", "filtered")
                except:
                    self.update_result(f"Port {port}/TCP is filtered (ACK).\n", "filtered")

        scan_func_map = {
            "TCP Connect Scan": scan_tcp_connect,
            "SYN Scan": scan_syn,
            "UDP Scan": scan_udp,
            "ACK Scan": scan_ack
        }

        scan_func = scan_func_map.get(scan_type)

        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_func, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        open_ports_str = ', '.join(map(str, open_ports)) if open_ports else "None"
        filtered_ports_str = ', '.join(map(str, filtered_ports)) if filtered_ports else "None"
        self.result_text.insert(tk.END, f"\nScan complete.\nOpen ports: {open_ports_str}\nFiltered ports: {filtered_ports_str}\n")

    def update_result(self, message, tag):
        self.result_text.insert(tk.END, message, tag)

    def save_results(self):
        result_text = self.result_text.get(1.0, tk.END)
        if not result_text.strip():
            messagebox.showwarning("Warning", "No results to save.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if save_path:
            with open(save_path, "w") as file:
                file.write(result_text)
            messagebox.showinfo("Info", "Results saved successfully.")

    def clear_results(self):
        self.result_text.delete(1.0, tk.END)

class TestAdvancedPortScanner(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = AdvancedPortScannerApp(self.root)

    def test_ip_entry_empty(self):
        self.app.ip_entry.delete(0, tk.END)
        self.app.port_entry.insert(0, "80-100")
        self.app.timeout_entry.insert(0, "0.5")
        self.app.start_scan()
        self.assertEqual(self.app.result_text.get(1.0, tk.END).strip(), "")
    
    def test_invalid_port_range(self):
        self.app.ip_entry.insert(0, "127.0.0.1")
        self.app.port_entry.delete(0, tk.END)
        self.app.port_entry.insert(0, "invalid")
        self.app.timeout_entry.insert(0, "0.5")
        self.app.start_scan()
        self.assertEqual(self.app.result_text.get(1.0, tk.END).strip(), "")
    
    def test_timeout_value(self):
        self.app.ip_entry.insert(0, "127.0.0.1")
        self.app.port_entry.insert(0, "80-100")
        self.app.timeout_entry.delete(0, tk.END)
        self.app.timeout_entry.insert(0, "invalid")
        self.app.start_scan()
        self.assertEqual(self.app.result_text.get(1.0, tk.END).strip(), "")
    
    def tearDown(self):
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedPortScannerApp(root)
    root.mainloop()
