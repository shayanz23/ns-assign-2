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
        parse_ip_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload

# byte 9 is protocol 2 hex digits = 1 byte
def parse_ip_header(hex_data):
    version = int(hex_data[:1], 16)
    header_length = int(hex_data[1:2], 16) * 4
    total_length = int(hex_data[4:8], 16)
    protocol_type = int(hex_data[18:20], 16)
    src_ip = hex_to_ip(hex_data[24:32])
    dst_ip = hex_to_ip(hex_data[32:40])

    flags_frags_offset = int(hex_data[12:16], 16)
    flags = flags_frags_offset >> 13 # Getting top 3 bits
    fragment_offset = flags_frags_offset & 0x1FFF

    reserved_flag = (flags >> 2) & 0x1 
    df_flag = (flags >> 1) & 0x1        
    mf_flag = flags & 0x1  

    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[:1]:<20} | {version}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {header_length} bytes")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Flags & Frag Offset:':<25} {hex_data[12:16]:<20} | {flags_frags_offset}")
    print(f"    {'Reserved:':<25} {reserved_flag}")
    print(f"    {'DF:':<25} {df_flag}")
    print(f"    {'MF:':<25} {mf_flag}")
    print(f"    {'Fragment Offset:':<25} {fragment_offset}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol_type}")
    print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {src_ip}")
    print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {dst_ip}")

    if protocol_type == 1:
        parse_icmp_header(hex_data[40:])
    elif protocol_type == 6:
        parse_tcp_header(hex_data[40:])
    elif protocol_type == 17:
        parse_udp_header(hex_data[40:])
    else:
        print("No parser available for this protocol type.")
    


def parse_icmp_header(hex_data):
    icmp_type = int(hex_data[0:2], 16)
    icmp_code = int(hex_data[2:4], 16)
    icmp_checksum = int(hex_data[4:8], 16)
    print("ICMP Header:")
    print(f"  Type:       {hex_data[0:2]} | {icmp_type}")
    print(f"  Code:       {hex_data[2:4]} | {icmp_code}")
    print(f"  Checksum:   {hex_data[4:8]} | {icmp_checksum}")
    print(f"  Payload (hex):   {hex_data[8:]}")

def parse_tcp_header(hex_data):
    src_port = int(hex_data[0:4], 16)
    dst_port = int(hex_data[4:8], 16)
    seq_num = int(hex_data[8:16], 16)
    ack_num = int(hex_data[16:24], 16)
    data_offset = int(hex_data[24:25], 16)
    reserved = int(hex_data[25:26], 16)
    flags = int(hex_data[26:28], 16)
    data_offset_bytes = data_offset * 4
    window = int(hex_data[28:32], 16)
    checksum = int(hex_data[32:36], 16)
    urgent_pointer = int(hex_data[36:40], 16)

    ns_flag = flags & 0x1
    cwr_flag = (flags >> 7) & 0x1
    ece_flag = (flags >> 6) & 0x1
    urg_flag = (flags >> 5) & 0x1
    ack_flag = (flags >> 4) & 0x1
    psh_flag = (flags >> 3) & 0x1
    rst_flag = (flags >> 2) & 0x1
    syn_flag = (flags >> 1) & 0x1
    fin_flag = flags & 0x1
    print("TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[0:4]:<20} | {src_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {dst_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {seq_num}")
    print(f"  {'Acknowledgment Number:':<25} {hex_data[16:24]:<20} | {ack_num}")
    print(f"  {'Data Offset:':<25} {data_offset:<20} | {data_offset_bytes} bytes")
    print(f"  {'Reserved:':<25} {bin(reserved):<20} | {reserved}")
    print(f"  {'Flags:':<25} {bin(flags):<20} | {flags}")
    print(f"    {'NS:':<20} {ns_flag}")
    print(f"    {'CWR:':<20} {cwr_flag}")
    print(f"    {'ECE:':<20} {ece_flag}")
    print(f"    {'URG:':<20} {urg_flag}")
    print(f"    {'ACK:':<20} {ack_flag}")
    print(f"    {'PSH:':<20} {psh_flag}")
    print(f"    {'RST:':<20} {rst_flag}")
    print(f"    {'SYN:':<20} {syn_flag}")
    print(f"    {'FIN:':<20} {fin_flag}")
    print(f"  {'Window Size:':<25} {hex_data[28:32]:<20} | {window}")
    print(f"  {'Checksum:':<25} {hex_data[32:36]:<20} | {checksum}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[36:40]:<20} | {urgent_pointer}")
    print(f"  {'Payload (hex):':<25} {hex_data[40:]}")

def parse_udp_header(hex_data):
    src_port = int(hex_data[:4], 16)
    dst_port = int(hex_data[4:8], 16)
    length = int(hex_data[8:12], 16)
    checksum = int(hex_data[12:16], 16)
    print("UDP Header:")
    print(f"  {'Source Port:':<20} {hex_data[:4]:<20} | {src_port}")
    print(f"  {'Destination Port:':<20} {hex_data[4:8]:<20} | {dst_port}")
    print(f"  {'Length:':<20} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum:':<20} {hex_data[12:16]:<20} | {checksum}")
    print(f"  Payload (hex): {hex_data[16:]}")

    if (dst_port == 53 or src_port == 53):
        parse_dns_header(hex_data[16:])
    else:
        print("No parser available for this port.")

def parse_dns_header(hex_data):
    id = int(hex_data[:4], 16)
    flags = int(hex_data[4:8], 16)
    qdcount = int(hex_data[8:12], 16)
    ancount = int(hex_data[12:16], 16)
    nscount = int(hex_data[16:20], 16)
    arcount = int(hex_data[20:24], 16)
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z = (flags >> 4) & 0x7
    rcode = flags & 0xF
    print("DNS Header:")
    print(f"  {'Transaction ID:':<20} {hex_data[:4]:<20} | {id}")
    print(f"  {'Flags:':<20} {hex_data[4:8]:<20} | {flags}")
    print(f"  {'  QR:':<20} {'':<20} | {qr}")
    print(f"  {'  Opcode:':<20} {'':<20} | {opcode}")
    print(f"  {'  AA:':<20} {'':<20} | {aa}")
    print(f"  {'  TC:':<20} {'':<20} | {tc}")
    print(f"  {'  RD:':<20} {'':<20} | {rd}")
    print(f"  {'  RA:':<20} {'':<20} | {ra}")
    print(f"  {'  Z:':<20} {'':<20} | {z}")
    print(f"  {'  RCODE:':<20} {'':<20} | {rcode}")
    print(f"  {'Questions:':<20} {hex_data[8:12]:<20} | {qdcount}")
    print(f"  {'Answer RRs:':<20} {hex_data[12:16]:<20} | {ancount}")
    print(f"  {'Authority RRs:':<20} {hex_data[16:20]:<20} | {nscount}")
    print(f"  {'Additional RRs:':<20} {hex_data[20:24]:<20} | {arcount}")
    print(f"  Payload (hex): {hex_data[24:]}")
    

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


