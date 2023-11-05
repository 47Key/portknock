import socket
import ipaddress
from colorama import init, Fore, Back, Style
import json

from time import sleep
from random import shuffle, uniform
import subprocess
from threading import Thread, Lock, RLock
from queue import Queue

import struct

popular_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
common_services = { 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "Microsoft-DS", 3306: "MySQL", 3389: "MS RDP", 5432: "PostgreSQL" }

class Scanner:
    def __init__(self, target, port_range="1-65535", mode="normal", output=False, format=None, threads=200):
        self.target = target
        self.port_range = port_range
        self.threads = threads
        self.mode = mode
        self.output = output
        self.format = format

        self.init_scanner()
    
    def init_scanner(self):
        self.ports_scanned = 0
        self.open_ports = []
        self.closed_ports = []
        self.lock = RLock()

        self.queue = Queue()
        self.print_lock = Lock()
    
        self.init_colorama()
        self.init_mode()
        self.init_port_range()

    def init_colorama(self):
        init()
        self.colorama = {
            "green": Fore.LIGHTGREEN_EX,
            "blue": Fore.LIGHTBLUE_EX,
            "red": Fore.RED,
            "gray": Fore.LIGHTBLACK_EX,
            "reset": Back.RESET,
            "style": Style.BRIGHT
        }

    def init_mode(self):
        mode = self.mode
        if (mode == "quiet"):
            self.rate_limit = 1000
            self.timeout = 2

        if (mode == "normal" or mode == "default"):
            self.rate_limit = 10000
            self.timeout = 1

        if (mode == "insane"): 
            self.rate_limit = 100000
            self.timeout = 0.5

        if (mode == "popular"):
            self.rate_limit = 100000
            self.timeout = 0.5
            self.ports = popular_ports

    def init_port_range(self):
        start_port, end_port = self.port_range.split("-")
        start_port, end_port = int(start_port), int(end_port)

        ports = [ p for p in range(start_port, end_port)]

        if ports is not None:
            self.ports = ports
        
        else:
            self.ports = self.port_range

    def detect_service(self, port, banner):
        service = common_services.get(port, "Unknown")
        return service
    
    def grab_banner(self, s):
        try:
            banner = s.recv(1024).decode().strip("\n")
        except:
            banner = None

        return banner

    def check_save_results(self, results):
        """Save the scan results to a file."""
        
        output, format = self.output, self.format

        green, blue, red, gray, reset, style = self.colorama.values()

        if not output:
            print(f'{style}{blue}Results of scan:\n {[res for res in results]}     {reset}')

        if format == 'json':
            with open('results.json', 'w') as f:
                json.dump(results, f)

        elif format == 'txt' or format is None:
            with open('results.txt', 'w') as f:
                for result in results:
                    f.write(str(result) + '\n')

    def check_subnet(self, target):
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts())
            shuffle(hosts)
            
            return hosts
        
        except ValueError:
            return [str(target)]
    
    def get_sleep_time(self, rate_limit, jitter):
        base_time = 1.0 / rate_limit
        jitter_time = base_time * jitter
        return uniform(base_time - jitter_time, base_time + jitter_time)

    def stealth__scan(self, host, port):
        """ Perform a stealth scan on a port. """
        green, blue, red, gray, reset, style = self.colorama.values()
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) 
            tcp_header = struct.pack("!HH16s", self.source_port, port, b'')

            s.sentto(tcp_header, (host, port))

            data, addr = s.recvfrom(1024)
            tcp_header = data[20:40]
            flags = struct.unpack("!H", tcp_header[12:14])[0]

            if flags & 0x12:
                return "Open"
            
            elif flags & 0x14:
                return "Closed"
            
        except Exception as e:
            print(f"{style}{red}Error while stealth scanning: {e}")

            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.settimeout(self.timeout)
            s.connect((str(host), port))
            banner = self.grab_banner(s)
            service = self.detect_service(port, banner)


    def ping_sweep(self, ip_range):
        live_hosts = []
        for ip in ip_range:
            try:
                output = subprocess.check_output(f"ping -c 1 {ip}", shell=True)
                if "1 packets received" in output:
                    live_hosts.append(ip)

            except:
                pass

        return live_hosts

    def port_scan(self, host, port):
        """
        Scan a port on the global variable `host`
        """
        green, blue, red, gray, reset, style = self.colorama.values()
        
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((str(host), port))
            banner = self.grab_banner(s)
            service = self.detect_service(port, banner)
            
            with self.lock:
                self.open_ports.append((port, service, banner))

        except (socket.timeout, socket.error):
            with self.lock:
                self.closed_ports.append(port)

        finally:
            s.close()

        with self.lock:
            self.ports_scanned += 1
            print(f"{style}{blue}Scanned: {self.ports_scanned} ports...{reset}", end='\r')
            
            sleep(
                self.get_sleep_time(self.rate_limit, 0.1)
            )

    def scan_thread(self):
        queue = self.queue
        green, blue, red, gray, reset, style = self.colorama.values()

        while True:
            worker = queue.get()
            host, port = worker
            
            try:
                self.port_scan(host, port)
                
            except Exception as e:
                with self.lock:
                    print(f"{style}{red}Error while scanning port: {e}     {reset}")
                
            queue.task_done()

    def start(self):
        queue, threads = self.queue, self.threads
        green, blue, red, gray, reset, style = self.colorama.values()

        hosts = self.check_subnet(self.target)

        for t in range(threads):
            t = Thread(target=self.scan_thread)
            t.daemon = True
            t.start()

        for host in hosts:
            for port in self.ports:
                queue.put((host, port))

        queue.join()

        print(f"\n\n{style}{blue}Scanned a total of {self.ports_scanned} ports.")
        print(f"{style}{green}Open Ports: {len(self.open_ports)}")
        print(f"{style}{red}Closed Ports: {len(self.closed_ports)}")

        results = self.open_ports

        self.check_save_results(results)

    