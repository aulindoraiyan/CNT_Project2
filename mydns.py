#!/usr/bin/env python3
import socket
import sys
import struct
import random

DNS_PORT = 53
TYPE_A   = 1
TYPE_NS  = 2
CLASS_IN = 1


# ------------------------------------------------------------------
# Shared helpers (used by Person 2, 3, and 4)
# ------------------------------------------------------------------

def parse_name(data, offset):
    """
    Decode a DNS domain name starting at `offset` in `data`.

    DNS names can use pointer compression (RFC 1035 §4.1.4):
      - A length byte < 0xC0 introduces a label of that many bytes.
      - A two-byte sequence starting with 0xC0 is a pointer; the
        lower 14 bits give the absolute offset of the rest of the name.
      - A zero length byte ends the name.

    Returns:
        (name_str, new_offset)
        new_offset is the position AFTER the name (or after the
        pointer bytes if a jump occurred).
    """
    labels    = []
    jumped    = False
    post_jump = None
    visited   = set()

    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)

        length = data[offset]

        if length == 0:
            offset += 1
            break

        elif (length & 0xC0) == 0xC0:
            if not jumped:
                post_jump = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset  = pointer
            jumped  = True

        else:
            offset += 1
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length

    name = ".".join(labels)
    return name, (post_jump if jumped else offset)


def parse_records(data, offset, count):
    """
    Parse `count` DNS resource records from `data` starting at `offset`.

    For TYPE_A  records, rdata is decoded as a dotted-quad IPv4 string.
    For TYPE_NS records, rdata is decoded as a domain name string.
    All other types keep rdata as raw bytes.

    Returns:
        (records_list, new_offset)
        Each record is a dict: {'name', 'type', 'rdata'}
    """
    records = []

    for _ in range(count):
        name, offset = parse_name(data, offset)

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset      += 10
        rdata_start  = offset
        offset      += rdlength

        if rtype == TYPE_A and rdlength == 4:
            rdata = ".".join(str(b) for b in data[rdata_start : rdata_start + 4])

        elif rtype == TYPE_NS:
            rdata, _ = parse_name(data, rdata_start)

        else:
            rdata = data[rdata_start : rdata_start + rdlength]

        records.append({"name": name, "type": rtype, "rdata": rdata})

    return records, offset


# ------------------------------------------------------------------
# PERSON 1 – Raiyan
# Send query to root DNS server (15%)
# ------------------------------------------------------------------

def build_dns_query(domain):
    """
    Build the DNS query packet.
    This includes:
    - DNS header
    - Question section
    """
    # Random transaction ID
    transaction_id = random.randint(0, 65535)

    # Flags = 0 for standard query with recursion not desired
    flags = 0

    # One question, no answers/authority/additional in query
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    # Build DNS header
    header = struct.pack("!HHHHHH",
                         transaction_id,
                         flags,
                         qdcount,
                         ancount,
                         nscount,
                         arcount)

    # Encode domain name into DNS format
    qname = b""
    for part in domain.strip(".").split("."):
        qname += struct.pack("!B", len(part))
        qname += part.encode("ascii")
    qname += b"\x00"

    # QTYPE = A, QCLASS = IN
    question = qname + struct.pack("!HH", TYPE_A, CLASS_IN)

    query_packet = header + question
    return query_packet


def send_query(server_ip, domain):
    """
    Send DNS query using UDP socket.
    """
    query_packet = build_dns_query(domain)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query_packet, (server_ip, DNS_PORT))

    return sock


# ------------------------------------------------------------------
# PERSON 2 – Henry
# Receive reply from root DNS server (15%)
# Display server reply content (10%)
# ------------------------------------------------------------------

def receive_reply(sock):
    """
    Receive a DNS UDP reply on the already-connected socket.

    Sets a 5-second timeout so the program doesn't hang forever
    if the server is unreachable or drops the packet.

    Returns:
        bytes  – raw DNS response payload, or
        None   – on timeout or network error
    """
    try:
        sock.settimeout(5)
        data, _ = sock.recvfrom(512)   # RFC 1035 §2.3.4 max UDP DNS msg = 512 B
        return data

    except socket.timeout:
        print("Error: Request timed out (no reply within 5 s).")
        return None

    except OSError as e:
        print(f"Error receiving reply: {e}")
        return None


def display_reply(data):
    """
    Parse a raw DNS reply and print its contents in the format
    required by the sample output, e.g.:

        Reply received. Content overview:
        0 Answers.
        6 Intermediate Name Servers.
        7 Additional Information Records.

        Answers section:
        Authority Section:
        Name : edu  Name Server: l.edu-servers.net
        ...
        Additional Information Section:
        Name : a.edu-servers.net  IP : 192.5.6.30
        ...

    Returns:
        dict with keys 'answers', 'authority', 'additional'
        (each a list of record dicts) so Person 3 and Person 4
        can consume the parsed data without re-parsing.
        Returns None if the payload is invalid.
    """
    if not data or len(data) < 12:
        print("Error: Response is too short to be a valid DNS message.")
        return None

    # Header (12 bytes): ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
    _id, _flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    offset = 12

    # Skip question section: QNAME (variable) + QTYPE(2) + QCLASS(2)
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4

    # Parse the three answer sections
    answers,    offset = parse_records(data, offset, ancount)
    authority,  offset = parse_records(data, offset, nscount)
    additional, offset = parse_records(data, offset, arcount)

    # Print summary
    print("Reply received. Content overview:")
    print(f"{ancount} Answers.")
    print(f"{nscount} Intermediate Name Servers.")
    print(f"{arcount} Additional Information Records.")

    # Answers section
    print("\nAnswers section: ")
    for rec in answers:
        if rec["type"] == TYPE_A:
            print(f"Name : {rec['name']}  IP: {rec['rdata']}")

    # Authority section
    print("Authority Section:")
    for rec in authority:
        if rec["type"] == TYPE_NS:
            print(f"Name : {rec['name']}  Name Server: {rec['rdata']}")

    # Additional Information section
    print("Additional Information Section:")
    for rec in additional:
        if rec["type"] == TYPE_A:
            print(f"Name : {rec['name']}  IP : {rec['rdata']}")

    return {
        "answers":    answers,
        "authority":  authority,
        "additional": additional,
    }


# ------------------------------------------------------------------
# PERSON 3 – Jacob
# Extract intermediate DNS server IP (15%)
# ------------------------------------------------------------------

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


# ------------------------------------------------------------------
# PERSON 4 – Jonathan
# Send query to intermediate servers (15%)
# Receive reply from intermediate servers (15%)
# Display IPs for queried domain name (15%)
# ------------------------------------------------------------------

def extract_final_ips(parsed_data, domain):
    """
    Check the Answers section for A records
    that match the queried domain.
    """
    if parsed_data is None:
        return []
    
    final_ips = []

    answers = parsed_data.get("answers", [])
    # Raiyan's fix: I noticed the previous version returned all A records, even unrelated ones.
    # I fixed it by checking that the record name matches the queried domain,
    # so only the correct IP(s) are returned.

    for record in answers:
        if record.get("type") == TYPE_A:
            name = record.get("name", "").strip(".").lower()
            if name == domain.strip(".").lower():
                ip = record.get("rdata")
                if ip:
                    final_ips.append(ip)

    return final_ips


# ------------------------------------------------------------------
# Main iterative lookup loop
# ------------------------------------------------------------------

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
        print("----------------------------------------------------------------")
        print("DNS server to query:", current_server)

        # send query
        sock = send_query(current_server, domain)

        # receive reply
        data = receive_reply(sock)
        if data is None:
            print("No response received.")
            return

        # display reply
        parsed_data = display_reply(data)

        # check if final answer found
        final_ips = extract_final_ips(parsed_data, domain)
        if final_ips:
            print("\nFinal Answer:")
            for ip in final_ips:
                print(f"Name : {domain}  IP: {ip}")
            return

        # otherwise get next DNS server
        next_ip = extract_next_dns_ip(parsed_data)
        if next_ip is None:
            print("No intermediate DNS server found.")
            return

        current_server = next_ip


# ------------------------------------------------------------------
# Main Program
# ------------------------------------------------------------------

def main():
    if len(sys.argv) != 3:
        print("Usage: python mydns.py domain-name root-dns-ip")
        return

    domain      = sys.argv[1]
    root_dns_ip = sys.argv[2]
    iterative_lookup(domain, root_dns_ip)


if __name__ == "__main__":
    main()
