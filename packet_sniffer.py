import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)                                               # iface=az interface, amit monitorozunk, store=mentjuk e a packeteket, vagy sem, prn=az a funkció, amit a monitorozás során a packeteken végre akarunk hajtani (callback function).


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):                                                                               # ellenőrzi, hogy a pcket rendelkezik e layerrel, és az HTTP request e.
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)                                                                               # [] közé tesszük a layer-t, amit keresünk, a '.load' a field a layeren belül, ami érdekel minket


sniff("eth0")
