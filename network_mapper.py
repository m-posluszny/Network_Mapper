from vlsm_calc import op_oct,get_oct_ip,show_oct,get_cidr_from_mask
from ipaddress import IPv4Network, IPv4Address
import nmap
import socket
import netifaces
from requests import get


class NetworkMapper:

    def __init__(self,iface):
        self.iface = iface
        self.nm = nmap.PortScanner()

    def dns_map(self,addresses):
        self.nm = nmap.PortScanner()
        self.nm.scan(addresses,arguments="-sL")
        dns_map = {}
        for host in self.nm.all_hosts():
            hostname = self.nm[host].hostname()
            ip = host
            if hostname != '':
                dns_map[ip]=hostname
        return dns_map

    def active_map(self,addresses):
        self.nm.scan(addresses,arguments="-sn")
        active_hosts=[]
        with open("active_hosts.txt","w") as f:
            for host in self.nm.all_hosts():
                is_active = self.nm[host].state()
                ip = host
                if is_active:
                    f.write(ip+"\n")
                    active_hosts.append(ip)
        return active_hosts, "-iL ./active_hosts.txt"

    def port_scan(self,addresses):
        self.nm.scan(addresses,arguments="-sS")
        unfiltered_hosts= []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                lport = self.nm[host][proto].keys()
                for port in lport:
                    state = self.nm[host][proto][port]['state']
                    if state == 'open':
                        if host not in unfiltered_hosts:
                            unfiltered_hosts.append(host)
        used_hosts = unfiltered_hosts[0:5] if (len(unfiltered_hosts) > 5 ) else unfiltered_hosts
        with open("unfilter_hosts.txt","w") as f:
            for host in used_hosts:
                f.write(host+"\n")
        return "-iL ./unfilter_hosts.txt"

    def light_scan(self,addresses,ommit_active=False):
        print("\nDNS mapping result")
        mapped_ip = self.dns_map(addresses)
        print("*",self.get_command())
        
        for ip,name in mapped_ip.items():
            print(ip,"-",name)
        if len(mapped_ip) == 0:
            print("No hostname found")
        print("Hosts mapped:",len(mapped_ip))
        file_flag = ""
        if not ommit_active:
            print("\nScanning active hosts")    
            active_hosts,file_flag = self.active_map(addresses)
            print("*",self.get_command())
            print("Active list")
            for ip in active_hosts:
                print(ip)
            print("Active count:",len(active_hosts))
        else:
            file_flag = addresses
        print("\nPort scan")
        nonfilter_file_flag = self.port_scan(file_flag)
        print("*",self.get_command())
        self.show_ports()
        return nonfilter_file_flag
    
    def deep_scan(self,address):
        print("\nOS & Version scan")
        self.os_version_scan(address)
        print("*",self.get_command())
        self.show_os_ver_scan()

    def show_ports(self):
        for host in self.nm.all_hosts():
            print(" Address :",host)
            for proto in self.nm[host].all_protocols():
                print('  Protocol : ',proto)
                lport = self.nm[host][proto].keys()
                for port in lport:
                    state = self.nm[host][proto][port]['state']
                    print(f'   Port : {port}\tstatus  {state}')

    def get_command(self):
        return self.nm.command_line()

    def os_version_scan(self,addresses):
        self.nm.scan(addresses,arguments="-O -sV")
    
    def show_os_ver_scan(self):
        for host in self.nm.all_hosts():
            print(" ")
            print(host)
            print(" OS Name",self.nm[host]['osmatch'][0]['name'])
            for proto in self.nm[host].all_protocols():
                port_keys = self.nm[host][proto].keys()
                for port in port_keys:
                    lport = self.nm[host][proto][port]
                    print(port,lport['product'],lport['version'])
                    print(f'   Port:{port}\tApp:"{lport["product"]}"\tVer:{lport["version"]}')


    def isp_scan(self,addresses):
        ...
    
    def site_scan(self,addresses):
        ...
    
    def get_ip_class_mask(self,ip):
        classA = IPv4Network(("10.0.0.0", "255.0.0.0"))  
        classB = IPv4Network(("172.16.0.0", "255.240.0.0")) 
        classC = IPv4Network(("192.168.0.0", "255.255.0.0"))
        ip_classes = {classA:8,classB:16,classC:24}
        ip = IPv4Address(ip)
        for ip_class,mask in ip_classes.items():
            if ip in ip_class:
                return mask
        else:
            return 8

    def get_external_ip(self):
        ip = get('https://api.ipify.org').text
        return ip

    def _is_valid_ipv4_address(self,address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count('.') == 3
        except socket.error: 
            return False

        return True

    def get_unix_dns_ips(self):
        dns_ips = []
        with open('/etc/resolv.conf') as fp:
            for cnt, line in enumerate(fp):
                columns = line.split()
                if columns[0] == 'nameserver':
                    ip = columns[1:][0]
                    if self._is_valid_ipv4_address(ip):
                        dns_ips.append(ip)
        return dns_ips

    
    def get_pc_configuration(self):
        ip_data = netifaces.ifaddresses(self.iface)[2]
        gws_data=netifaces.gateways()
        gateway = ""
        if self.iface in gws_data[2][0]:
            gateway = gws_data[2][0][0]
        return ip_data[0]['addr'],ip_data[0]['netmask'],gateway

    def get_network_address(self):
        myip, mask, gateway = self.get_pc_configuration()
        cidr = get_cidr_from_mask(mask)
        newtork_ip = show_oct(op_oct(get_oct_ip(myip),"&",get_oct_ip(mask)))
        return f'{newtork_ip}/{cidr}'
    
