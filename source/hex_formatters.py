# This function converts ip hex into a mac address with octets and 
# returns it.
def hex_to_mac(hex_mac):
    octet_list = []
    mac_string = ""
    for i in range(0, len(hex_mac), 2):
        tmp = hex_mac[i:i+2]
        octet_list.append(tmp)
    mac_string = ':'.join(octet_list)
    return mac_string

# This function converts ip hex into a decimal ip address with octets and 
# returns it.
# 4 8 bit numbers, 32 total, octet is 8 total, 8 * 4 = 32 therefore 8/4 = 2. 
# Each 2 digits are one 4th of the ip address.
def hex_to_ip(hex_ip):
    octet_list = []
    ip_string = ""
    for i in range(0, len(hex_ip), 2):
        tmp = hex_ip[i:i+2]
        num = int(tmp, 16)
        octet_list.append(num)
    ip_string = '.'.join(str(x) for x in octet_list)
    return ip_string

