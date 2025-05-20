from scapy.all import IP, UDP, TCP, ICMP, sr1
import time
import socket
import threading
import ssl
from random import randint
import select

class PortScanner:
    __slots__ = ("host", "port", "timeout")

    def __init__(self, host = "", port = (1, 101), timeout = 1):
        self.host = host
        self.port = port
        self.timeout = timeout

    def __repr__(self):
        return f"<PortScanner: Host={self.host}, Port={self.port}, Timeout={self.timeout}>"

    def __str__(self):
        return f"Host: {self.host}, Port: {self.port}"
    
    def tcp_scan(self):
        open_ports = []
        closed_ports = []
        filtered_ports = []

        for port in range(self.port[0], self.port[1]):
            pkt = IP(dst=self.host)/TCP(dport=port, flags="S")  # SYN packet
            print(f"Scanning TCP port {port}...\n")
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            if response is None:
                print(f"TCP port {port} is filtered (no response)\n")
                filtered_ports.append(port)  # No response = filtered or silently dropped
                time.sleep(0.1)
            elif response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    open_ports.append(port)
                    print(f"TCP port {port} is open\n")
                    time.sleep(0.1)
                    sr1(IP(dst=self.host)/TCP(dport=port, flags="R"), timeout=1, verbose=0) #RST packet to close the connection
                elif response[TCP].flags == 0x14:  # RST-ACK
                    closed_ports.append(port)
                    time.sleep(0.1)
            else:
                closed_ports.append(port)
                time.sleep(0.1)


        print(f"Open TCP ports: {open_ports}\n\n")
        print(f"Closed TCP ports: {closed_ports}\n\n")
        print(f"Filtered TCP ports: {filtered_ports}\n\n")
    
    def udp_scan(self):
        udp_open_ports = []
        udp_closed_ports = []
        udp_filtered_ports = []

        for port in range(self.port[0], self.port[1]):
            pkt = IP(dst=self.host)/UDP(dport=port)
            print(f"Scanning UDP port {port}...\n")
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp is None:
                udp_filtered_ports.append(port)
                time.sleep(0.1)  
            elif resp.haslayer(ICMP):
                icmp_type = resp.getlayer(ICMP).type
                icmp_code = resp.getlayer(ICMP).code
                if icmp_type == 3 and icmp_code == 3:
                    udp_closed_ports.append(port)
                    time.sleep(0.1)
                else:
                    udp_filtered_ports.append(port)  #Inconclusive response is sent to filtered list
                    time.sleep(0.1)
            elif resp.haslayer(UDP):
                print(f"UDP port {port} is open\n")
                udp_open_ports.append(port)
                time.sleep(0.1)  # Throttle the scan to avoid overwhelming the target
            else:
                print(f"Port {port} is in an unknown state\n")
                udp_open_ports.append(port)
                time.sleep(0.1)  # Throttle the scan to avoid overwhelming the target
        print(f"Open UDP ports: {udp_open_ports}\n\n")
        print(f"Closed UDP ports: {udp_closed_ports}\n\n")
        print(f"Filtered UDP ports: {udp_filtered_ports}\n\n")

    def ping_scan(self):
        print(f"Pinging {self.host}...\n")
        pkt = IP(dst=self.host)/ICMP()
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp is None:
            print(f"{self.host} is down or not responding\n")
        else:
            print(f"{self.host} is up and responding\n")

    def banner_grabbing(self):
        threads = []
        failed_ports_tcp = []
        failed_ports_udp = []

    # Protocol-specific payloads
        protocol_payloads = {
            21: b"",  # FTP often auto-sends banner
            22: b"",  # SSH auto-sends
            23: b"",  # Telnet auto-sends
            25: b"HELO example.com\r\n",  # SMTP
            53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",  # DNS query
            67: b"",  # DHCP rarely replies without handshake
            80: b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n",  # HTTP
            123: b"",  # NTP requires special formatting (can be silent)
            443: b"",  # HTTPS often auto-sends
            445: b"",# SMB often auto-sends
} 

        def grab_tcp(port):
            try:
                if port == 443:
                    context = ssl.create_default_context()
                    with socket.create_connection((self.host, port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                            ssock.send(b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(self.host).encode())
                            banner = ssock.recv(1024)
                            print(f"[TCP {port}] Banner:\n{banner.decode(errors='ignore').strip()}\n")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((self.host, port))
                    payload = protocol_payloads.get(port, b"GET / HTTP/1.0\r\n\r\n")
                    if isinstance(payload, str):
                        payload = payload.format(self.host).encode()
                    s.send(payload)
                    banner = s.recv(1024)
                    print(f"[TCP {port}] Banner:\n{banner.decode(errors='ignore').strip()}\n")
            except Exception as e:
                failed_ports_tcp.append((port, str(e)))

        def grab_udp(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    payload = protocol_payloads.get(port, b"\x00")
                    s.sendto(payload, (self.host, port))
                    banner, _ = s.recvfrom(1024)
                    print(f"[UDP {port}] Banner:\n{banner.decode(errors='ignore').strip()}\n")
            except Exception as e:
                failed_ports_udp.append((port, str(e)))

        for port in range(self.port[0], self.port[1]):
            t_tcp = threading.Thread(target=grab_tcp, args=(port,))
            t_udp = threading.Thread(target=grab_udp, args=(port,))
            t_tcp.start()
            t_udp.start()
            threads.extend([t_tcp, t_udp])
            time.sleep(0.1)  #Throttles thread creation slightly to avoid overwhelming the host

        for t in threads:
            t.join()

        print(f"\nFailed TCP banner grabs: {failed_ports_tcp}\n")
        print(f"Failed UDP banner grabs: {failed_ports_udp}\n")


__all__ = ["PortScanner"]


if __name__ == "__main__":
    scanner_test = PortScanner(host="scanme.nmap.org")
    #scanner_test.banner_grabbing()