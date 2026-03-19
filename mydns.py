#!/usr/bin/env python3

import socket
import sys
import struct
import random

DNS_PORT = 53
TYPE_A = 1
TYPE_NS = 2
CLASS_IN = 1



# PERSON 1
# Send query to root DNS server (15%)


def build_dns_query(domain):
    """
    Build the DNS query packet.
    This includes:
    - DNS header
    - Question section
    """

    # TODO: Person 1
    # 1. Create DNS header using struct.pack
    # 2. Encode domain name into DNS format
    # 3. Add QTYPE and QCLASS

    query_packet = b''

    return query_packet


def send_query(server_ip, domain):
    """
    Send DNS query using UDP socket.
    """

    # TODO: Person 1
    # 1. Create UDP socket
    # 2. Call build_dns_query()
    # 3. Send packet to server_ip on port 53

    sock = None

    return sock



# PERSON 2
# Receive reply from root DNS server (15%)
# Display server reply content (10%)


def receive_reply(sock):
    """
    Receive DNS reply from server.
    """

    # TODO: Person 2
    # 1. Use recvfrom() to receive response
    # 2. Handle timeout errors

    data = None

    return data


def display_reply(data):
    """
    Display DNS reply content.
    Should print:
    - number of answers
    - number of authority records
    - number of additional records
    """

    # TODO: Person 2
    # 1. Parse DNS header (first 12 bytes)
    # 2. Extract ANCOUNT, NSCOUNT, ARCOUNT
    # 3. Print summary like sample output

    parsed_data = None

    return parsed_data



# PERSON 3
# Extract intermediate DNS server IP (15%)


def extract_next_dns_ip(parsed_data):
    """
    Look at the Additional section.
    Find an A record containing the IP
    of the next DNS server.
    """

    # TODO: Person 3
    # 1. Iterate through additional records
    # 2. Identify TYPE_A records
    # 3. Return the IP address

    next_ip = None

    return next_ip


# PERSON 4
# Send query to intermediate servers (15%)
# Receive reply from intermediate servers (15%)
# Display IPs for queried domain name (15%)


def extract_final_ips(parsed_data, domain):
    """
    Check the Answers section for A records
    that match the queried domain.
    """

    final_ips = []

    answers = parsed_data.get("answers", [])

    for record in answers:
        if record.get("type") == TYPE_A:
            ip = record.get("rdata")
            if ip:
                final_ips.append(ip)

    return final_ips


def iterative_lookup(domain, root_ip):
    """
    Perform iterative DNS lookup.

    Steps:
    1. Query root server
    2. Get intermediate DNS server
    3. Query intermediate server
    4. Repeat until A record found
    """

    current_server = root_ip

    while True:

        print("------------------------------------------------")
        print("DNS server to query:", current_server)

        # send query
        sock = send_query(current_server, domain)

        # receive reply
        data = receive_reply(sock)

        if data is None:
            print("No response received")
            return

        # display reply
        parsed_data = display_reply(data)

        # check if final answer found
        final_ips = extract_final_ips(parsed_data, domain)

        if final_ips:
            print("Final Answer:")
            for ip in final_ips:
                print(domain, "IP:", ip)
            return

        # otherwise get next DNS server
        next_ip = extract_next_dns_ip(parsed_data)

        if next_ip is None:
            print("No intermediate DNS server found.")
            return

        current_server = next_ip



# MAIN PROGRAM


def main():

    if len(sys.argv) != 3:
        print("Usage: python mydns.py domain-name root-dns-ip")
        return

    domain = sys.argv[1]
    root_dns_ip = sys.argv[2]

    iterative_lookup(domain, root_dns_ip)


if __name__ == "__main__":
    main()