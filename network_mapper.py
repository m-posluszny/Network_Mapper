from vlsm_calc import op_oct,get_oct_ip,show_oct,get_cidr_from_mask
from ipaddress import IPv4Network
import nmap
import socket
import netifaces
from requests import get


class NetworkMapper:

    def __init__(self,iface):
        self.iface = iface

    def basic_scan(self,addresses):
        nm = nmap.PortScanner()
        nm.scan(addresses,arguments="-sL")
        print("\n*",nm.command_line())
        names_counter = 0
        print("DNS mapping result")
        for host in nm.all_hosts():
            hostname = nm[host].hostname()
            ip = host
            if hostname == '':
                hostname = "no_hostname"
            else:
                names_counter+=1
                print(ip," - ", hostname)
        print("Hostname mapped:",names_counter)

        nm.scan(addresses,arguments="-sn")
        print("\n*",nm.command_line())
        active_hosts=[]
        print("Scanning active hosts")
        with open("active_hosts.txt","w") as f:
            for host in nm.all_hosts():
                is_active = nm[host].state()
                ip = host
                if is_active:
                    f.write(ip+"\n")
                    active_hosts.append(ip)
                    print(ip)
        print("Active count :",len(active_hosts))

        nm.scan("-iL ./active_hosts.txt",arguments="-sS")
        print("\n*",nm.command_line())
        print("Port scan")
        unfiltered_hosts= []
        for host in active_hosts:
            print(" Address :",host)
            for proto in nm[host].all_protocols():
                print('  Protocol : ',proto)
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    if host not in unfiltered_hosts:
                        unfiltered_hosts.append(host)
                    print(f'   Port : {port}\tstatus  {state}')
            
        used_hosts = unfiltered_hosts[0:5] if (len(unfiltered_hosts) > 5 ) else unfiltered_hosts
        with open("unfilter_hosts.txt","w") as f:
            for host in used_hosts:
                f.write(host+"\n")
        return "-iL ./unfilter_hosts.txt"

       

    def advanced_scan(self,addresses):
        nm = nmap.PortScanner()
        nm.scan(addresses,arguments="-O -sV")

        print("\n*",nm.command_line())
        print("OS and Version scan")
        for host in nm.all_hosts():
            print(host,nm[host]['osmatch'],nm[host]['vendor'])
            for proto in nm[host].all_protocols():
                port_keys = nm[host][proto].keys()
                for port in port_keys:
                    lport = nm[host][proto][port]
                    print(port,lport['product'],lport['version'])

    def isp_scan(self,addresses):
        ...
    
    def site_scan(self,addresses):
        ...
    
    def get_ip_class_mask(self,ip):
        classA = IPv4Network(("10.0.0.0", "255.0.0.0"))  
        classB = IPv4Network(("172.16.0.0", "255.240.0.0")) 
        classC = IPv4Network(("192.168.0.0", "255.255.0.0"))
        ip_classes = {classA:8,classB:16,classC:24}
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
    
