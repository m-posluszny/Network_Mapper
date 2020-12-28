import nmap
import netifaces
from VLSM_Subnets_Calculator.vlsm_calc import *
import platform
import socket
import subprocess

class NetworkMapper:

    def __init__(self,iface):
        self.scanner = nmap.PortScanner() 
        self.iface = iface

    def local_scan(addresses):
        ...

    def isp_scan(addresses):
        ...
    
    def isp_scan(addresses):
        ...

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
    
