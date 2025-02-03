# Parse Ethernet header
from hex_formatters import hex_to_ip, hex_to_mac


def parse_ethernet_header(hex_data):
    dest_mac = hex_to_mac(hex_data[0:12])
    source_mac = hex_to_mac(hex_data[12:24])
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)
    elif ether_type == "0800":
        print
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    # each hex represents 4 bits, therefore 2 represent 1 byte.
    hardware_type = int(hex_data[:4], 16) # 2 bytes
    protocol_type = int(hex_data[4:8], 16) # 2 bytes
    hardware_size = int(hex_data[8:10], 16) # 1 byte
    protocol_size = int(hex_data[10:12], 16) # 1 byte
    operation = int(hex_data[12:16], 16) # 2 bytes
    sender_mac = hex_data[16:28] # 6 bytes
    sender_ip = hex_data[28:36] # 4 bytes
    target_mac = hex_data[36:48] # 6 bytes
    target_ip = hex_data[48:56] # 4 bytes

    sender_mac_formatted = hex_to_mac(sender_mac)
    target_mac_formatted = hex_to_mac(target_mac)
    sender_ip_formatted = hex_to_ip(sender_ip)
    target_ip_formatted = hex_to_ip(target_ip)

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {operation}")
    print(f"  {'Sender MAC:':<25} {hex_data[16:28]:<20} | {sender_mac_formatted}")
    print(f"  {'Sender IP:':<25} {hex_data[28:36]:<20} | {sender_ip_formatted}")
    print(f"  {'Target MAC:':<25} {hex_data[36:48]:<20} | {target_mac_formatted}")
    print(f"  {'Target IP:':<25} {hex_data[48:56]:<20} | {target_ip_formatted}")


