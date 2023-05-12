# %%
import logging

logging.basicConfig(
    format="%(asctime)s ; %(levelname)s ; %(message)s",
    level=logging.INFO
)
logging.getLogger("scapy").setLevel(logging.CRITICAL)
log = logging.getLogger("adAPT")

from pathlib import Path
from collections import Counter
from time import perf_counter
from typing import Any, Dict, List

# import tensorflow as tf
import pandas as pd
# import numpy as np
from scapy import all as sp
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS

from valid_tlds import TLDS

sp.load_layer("http")


perf_start = perf_counter()
FILE_DIR = Path("~/GitRepos/challenge-datasets/").expanduser()
BENIGN_DIR = FILE_DIR / "benign"
MALWAR_DIR = FILE_DIR / "malware"

BENIGN_FILES = list([f for f in BENIGN_DIR.iterdir() if str(f).endswith(".pcap") or str(f).endswith(".pcapng")])
MALWAR_FILES = list([f for f in MALWAR_DIR.iterdir() if str(f).endswith(".pcap") or str(f).endswith(".pcapng")])


assert BENIGN_DIR.exists(), "Benign dir cannot be found"
assert MALWAR_DIR.exists(), "Malware dir cannot be found"
log.debug(f"Loaded files in {perf_counter() - perf_start} seconds.")

EXCLUDE_NAMES = ["Ethernet", "802.3", "cooked linux", "MPacket Preamble"]
INTERESTING_SERVICE_PORTS = [80, 443, 22, 53, 21, 20, 25, 465]
IGNORE_SERVICE_PORTS = list(range(20))  # skip packets with ports lower than 20
IGNORE_SERVICE_PORTS.append(37)  # time protocol
IGNORE_SERVICE_PORTS + [67, 68]  # BOOTP protocol
IGNORE_SERVICE_PORTS.append(123)  # NTP protocol
IGNORE_SERVICE_PORTS.append(179)  # bgp protocol
IGNORE_SERVICE_PORTS + [520, 521]  # RIP* protocol
IGNORE_SERVICE_PORTS.append(646)  # ldp protocol
IGNORE_SERVICE_PORTS.append(1967)  # CISCO IOS SLA protocol
IGNORE_SERVICE_PORTS.append(1985)  # HSRP protocol
IGNORE_SERVICE_PORTS + [5246, 5247]  # CAPWAP protocol


# ensure no interesting ports are ignored
IGNORE_SERVICE_PORTS = list(
    set(IGNORE_SERVICE_PORTS).difference(set(INTERESTING_SERVICE_PORTS))
)

class Protocol:
    UDP = 17
    IPv4 = 6
    IPv6 = 34525
    IPv6_enc = 41
    

class App:
    Unknown = "Unknown"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    FTP = "FTP"
    SSH = "SSH"
    SMTP = "SMTP"
    HTTPResponse = "HTTPResponse"
    HTTPRequest = "HTTPRequest"
    DNSQR = "DNSQueryRequest"
    DNSRR = "DNSRequestResponse"

    
HTTP_METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    

def get_proto(pkt: sp.Packet) -> Any:
    try:
        if pkt.proto == Protocol.IPv6 or pkt.proto == Protocol.IPv6_enc:
            return sp.IPv6
        if pkt.proto == Protocol.IPv4:
            return sp.IP
        if pkt.proto == Protocol.UDP:
            return sp.UDP
        return None
    except:
        return None
    

def identify_layers(pkt: sp.Packet) -> App:
    if HTTPRequest in pkt:
        return App.HTTPRequest
    elif HTTP in pkt or HTTPResponse in pkt:
        return App.HTTPResponse
    elif DNS in pkt:
        if pkt[DNS].an:
            return App.DNSRR
        elif pkt[DNS].qd:
            return App.DNSQR
        return App.DNS
    elif sp.Raw in pkt:
        try:
            lines = pkt.load.decode().split("\n")
            log.debug(f"identifying raw from lines[0]: {lines[0]}")
            if lines[0].split(" ")[0] in HTTP_METHODS:
                return App.HTTPRequest
        except Exception as e:
            pass
    else:
        pass
    return App.Unknown


def decode_if_able(d: Dict, key_filter: List[str] = None) -> Dict:
    ALWAYS_FILTER = ["flags"]
    if key_filter is None:
        key_filter = []
    outd = {}
    for k, v in d.items():
        if k in key_filter + ALWAYS_FILTER:
            continue
        k = k.lower()
        try:
            outd[k] = v.decode()
        except:
            outd[k] = v
    return outd


def gen_http_request_features(pkt: sp.Packet) -> Dict:
    if sp.Raw in pkt:
        raw_text = pkt[sp.Raw].load.decode()
        lines = raw_text.split("\n")
        method, path, http_version = [x.strip() for x in lines[0].split(" ", maxsplit=3)]
        _, host = [x.strip() for x in lines[1].split(": ")]
        _, user_agent = [x.strip() for x in lines[2].split(": ")]
        _, accept = [x.strip() for x in lines[3].split(": ")]
        _, accept_language = [x.strip() for x in lines[4].split(": ")]
        _, accept_encoding = [x.strip() for x in lines[5].split(": ")]
    else:
        req = pkt[HTTPRequest]
        method = req.Method.decode()
        path = req.Path.decode()
        host = req.Host.decode()
        user_agent = req.User_Agent.decode()
        accept = req.Accept.decode()
        accept_language = req.Accept_Language.decode()
        accept_encoding = req.Accept_Encoding.decode()
        http_version = req.Http_Version.decode()

    d = {
        "method": method,
        "path": path,
        "host": host,
        "user_agent": user_agent,
        "accept": accept,
        "accept_language": accept_language,
        "accept_encoding": accept_encoding,
        "http_version": http_version,
    }

    return d


def gen_http_response_features(pkt: sp.Packet) -> Dict:
    resp = pkt[HTTPResponse]
    raw_text = pkt[sp.Raw].load.decode()
    d = decode_if_able(resp.fields)
    d["raw_text"] = raw_text
    return d

def gen_dns_request_features(pkt: sp.Packet) -> Dict:
    qd = {}
    if pkt[DNS].qd:
        qd = decode_if_able(pkt[DNS].qd.fields)
    return qd


def gen_dns_response_features(pkt: sp.Packet) -> Dict:
    qd = {}
    an = {}
    if pkt[DNS].qd:
        qd = decode_if_able(pkt[DNS].qd.fields)
    if pkt[DNS].an:
        an = decode_if_able(pkt[DNS].an.fields)
    qd.update(an)
    return qd


def parse_data(pkt: sp.Packet, app: App) -> Dict:
    """ Turn a Raw payload into a dictionary of data """
    log.debug("entering parse_raw...")
    if app != App.Unknown:
        log.debug(f"Identified app: {app}")

    try:
        if app == App.HTTPRequest:
            return gen_http_request_features(pkt)
        if app == App.HTTPResponse:
            return gen_http_response_features(pkt)
        if app == App.DNSQR:
            return gen_dns_request_features(pkt)
        if app == App.DNSRR:
            return gen_dns_response_features(pkt)
        # add other feature generators here
        if sp.Raw in pkt:
            # log.warning(f"Could not parse {pkt}")
            return {"raw": pkt[sp.Raw].load.decode()}
    except Exception as e:
        return {"error": "could not parse packet data"}
    

def get_url(d: dict) -> str:
    if d is None:
        return None
    url = None
    if "host" in d:
        url = d["host"]
    if "qname" in d:
        url = d["qname"]
    if not isinstance(url, str):
        return ""
    if url.endswith("."):
        url = url[:-1]
    return url

def get_tld(s):
    bd = get_base_domain(s)
    if not bd:
        return None
    # split off the first part
    parts = bd.split(".", maxsplit=1)
    if len(parts) > 1:
        parts.pop(0)
        return parts[0]
    return bd
    
def get_base_domain(s: str) -> str:
    if not isinstance(s, str):
        return s
    if not "." in s:
        return ""
    index = 0
    for tld in TLDS:
        if s.endswith("." + tld):
            tld_parts = tld.split(".")
            index = len(tld_parts)
            break
    if not index:
        return ""  # not a valid tld
    index = index + 1
    parts = s.rsplit(".", maxsplit=index)
    return ".".join(parts[-1 * index:])

def get_host_part(s: str) -> str:
    if not isinstance(s, str):
        return s
    if not "." in s:
        return ""
    base_domain = get_base_domain(s)
    if base_domain:
        tail_length = -1 * len(base_domain) - 1
    else:
        tail_length = len(s)
    return s[:tail_length]  # extra -1 to account for trailing "."

    
def make_rows(pkts: sp.PacketList) -> List[Dict]:
    """ Read a packet, output a dict of values """
    
    log.debug(f"Filtering packets on IP, IPv6, and UDP")

    for pkt in pkts[sp.IP] + pkts[sp.IPv6] + pkts[sp.UDP]:
        proto = get_proto(pkt)

        log.debug(f"Identified proto as {proto}")
        try:
            if sp.IP not in pkt:
                log.debug("Skipping packet without IP layer.")
                continue
            try:
                pkt[proto].sport
                pkt[proto].dport
                pkt[sp.IP].src
                pkt[sp.IP].dst

            except:
                # this is not a packet with necessary attrs
                # log.warning("Could not find necessary attributes in packet, skipping...")
                continue
            if pkt[proto].sport in IGNORE_SERVICE_PORTS or pkt[proto].dport in IGNORE_SERVICE_PORTS:
                # skip packets with certain service ports
                continue
            parsed = None
            layer = identify_layers(pkt)
            if layer != App.Unknown:
                log.debug(f"Found app layer {layer} in packet. Parsing...")
                parsed = parse_data(pkt, layer)
            url = get_url(parsed)
            tld = get_tld(url)
            base_domain = get_base_domain(url)
            host = get_host_part(url)
            row = {
                "protocol": pkt[proto].name,
                "app_layer": layer,
                "source_addr": pkt[sp.IP].src,
                "dest_addr": pkt[sp.IP].dst,
                "source_port": pkt[proto].sport,
                "dest_port": pkt[proto].dport,
                "proto_packet_length": pkt[proto].len,
                "proto_packet_cache": pkt[proto].raw_packet_cache,
                "ip_packet_length": pkt[proto].len,
                "ip_packet_cache": pkt[sp.IP].raw_packet_cache,
                "parsed": parsed,
                "url": url,
                "tld": tld,
                "base_domain": base_domain,
                "host": host,
            }
            log.debug(f"Yielding {row}...")
            yield row
        except Exception as e:
            # log.exception(f"Error running make_rows with pkt: {pkt}")
            continue
    
def main():
    dfs = []
    for fn in BENIGN_FILES:
        with open(fn, "rb") as f:
            log.info(f"Reading {fn}...")
            start_perf = perf_counter()
            rows = list(make_rows(sp.rdpcap(f)))
            log.info(f"Processing pcap took {perf_counter() - start_perf} seconds.")
            dfs.append(pd.DataFrame(rows))
    benign_df = pd.concat(dfs)

    dfs = []

    for fn in MALWAR_FILES:
        with open(fn, "rb") as f:
            log.info(f"Reading {fn}...")
            start_perf = perf_counter()
            rows = list(make_rows(sp.rdpcap(f)))
            log.info(f"Processing pcap took {perf_counter() - start_perf} seconds.")
            dfs.append(pd.DataFrame(rows))
    malware_df = pd.concat(dfs)
    
    log.debug(f"benign_df.shape: {benign_df.shape}")
    log.debug(f"malware_df.shape: {malware_df.shape}")

    b_pkl = "./data/benign_features.pkl"
    m_pkl = "./data/malicious_features.pkl"
    log.info(f"Writing output bengign dataframe (with {benign_df.shape[0]} rows) to: {b_pkl}")
    benign_df.to_pickle(b_pkl)
    log.info(f"Writing output malicious dataframe (with {malware_df.shape[0]} rows) to: {m_pkl}")
    malware_df.to_pickle(m_pkl)

if __name__ == "__main__":
    main()

# %%
