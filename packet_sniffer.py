import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)                                               # iface=az interface, amit monitorozunk, store=mentjuk e a packeteket, vagy sem, prn=az a funkció, amit a monitorozás során a packeteken végre akarunk hajtani (callback function).


def process_sniffed_packet(packet):
    print(packet)


sniff("eth0")
