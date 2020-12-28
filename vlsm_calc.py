import math
import argparse

def get_data(ip):
    splt = ip.split("/")
    ip = splt[0]
    mask = int(splt[1])
    return ip,mask

def get_oct_ip(ip):
    ip_array=ip.split(".")
    octet=[]
    for part in ip_array:
        octet.append(int(part))
    return octet

def bit_not(n, numbits=8):
    return (1 << numbits) - 1 - n

def get_oct_cidr(cidr):
    i = cidr
    octets = []
    while(len(octets) < 4):
        if (i >= 8):
            octets.append((2**8-1))
        elif (8 >= i > 0):
            octets.append((2**i-1)<<8-i)
        else:
            octets.append(0)
        i = i-8
    return octets

def get_cidr_from_mask(oct):
        mask_array=oct.split(".")
        octet=[]
        cidr = 0
        for part in mask_array:
            binary = bin(int(part))[2:]
            cidr += binary.count('1')
        return cidr

def op_oct(oct1,op,oct2):
    new_oct=[]
    for i in range(0,4):
        if op == "&":
            new_oct.append(oct1[i] & oct2[i])
        elif op == "+":
            new_oct.append(oct1[i] + oct2[i])
    return new_oct

def not_oct(octets):
    neg_oct = []
    for octet in octets:
        neg_oct.append(bit_not(octet))
    return neg_oct


def add_to_oct(octets,val):
    origin = octets.copy()
    for x in range(3,-1,-1):
        if val > 255:
            val -= 255
            origin[x] = 255
        elif val+origin[x] > 255:
            val = val + origin[x] - 255
            origin[x] = 255
        elif val+origin[x]<0:
            return origin
        else:
            origin[x]+=val
            return origin
    
def get_cidr_log(hosts):
    cidr=int(32-math.log(hosts+2,2))
    return cidr

def max_hosts(cidr):
    return (2**(32-cidr))-2

def show_oct(my_oct):
    str_oct = ""
    for octet in my_oct:
        str_oct+=str(octet)+"."
    return str_oct[:-1]

def show_ip(ip_oct,cidr):
    return show_oct(ip_oct)+"/"+str(cidr)

def get_broadcast(ip_oct,mask):
    neg_mask = not_oct(mask)
    broadcast = op_oct(ip_oct,"+",neg_mask)
    return broadcast

def get_subnets_info(ip_v4, hosts_number):
    ip,cidr = get_data(ip_v4)
    ip_octets = get_oct_ip(ip)
    for hosts in hosts_number:
        print("-----------------")
        cidr = get_cidr_log(hosts)
        mask = get_oct_cidr(cidr)
        broadcast_ip  = get_broadcast(ip_octets,mask)
        first_host = add_to_oct(ip_octets,1)
        last_host = add_to_oct(broadcast_ip,-1)
        print("Adres podsieci",show_ip(ip_octets,cidr))
        print("Maska podsieci",show_oct(mask))
        print("Adres pierwszego hosta",show_oct(first_host))
        print("Adres ostatniego hosta",show_oct(last_host))
        print("Adres broadcast",show_oct(broadcast_ip))
        print("Max hostow",max_hosts(cidr))
        print("Hosty niewykorzystane",max_hosts(cidr)-hosts)
        ip_octets = add_to_oct(broadcast_ip,1)
    print("-----------------")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get Subnets of provided ip and host amounts')
    parser.add_argument('ip_with_cidr', help='example 203.203.203.0/24')
    parser.add_argument('hosts_amounts',  nargs="+",type=int,help='example 60 50 40')
    args = parser.parse_args()
    get_subnets_info(args.ip_with_cidr,args.hosts_amounts)
