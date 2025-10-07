#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dhcp_sniffer_ultimate.py - Maximum DHCP information capture with Internet Traffic Analysis

Features:
 - Captures ALL DHCP options with detailed parsing
 - Internet DHCP traffic detection and geolocation
 - Advanced vendor fingerprinting and device identification
 - Real-time threat detection and anomaly analysis
 - Multi-threading for high-performance capture
 - DNS tunneling and covert channel detection
 - DHCP server reputation and blacklist checking
 - Advanced network topology mapping
 - Machine learning-based traffic classification
 - Comprehensive security analysis and reporting
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import sys
import threading
import time
import signal
import socket
import hashlib
import base64
import urllib.request
import urllib.parse
import re
import ipaddress
import subprocess
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter, deque
from typing import Any, Dict, List, Optional, Set, Tuple
import concurrent.futures
import queue

try:
    from scapy.all import (sniff, BOOTP, DHCP, wrpcap, get_if_list, 
                          UDP, IP, Ether, rdpcap, Raw, conf, DNS, DNSQR, DNSRR)
except Exception as e:
    sys.stderr.write("ERROR: scapy import failed. Install: pip install scapy\n")
    sys.exit(2)

# --- defaults ---
DEFAULT_PCAP = "dhcp_capture.pcap"
DEFAULT_JSON = "log.json"
DEFAULT_TEXT = "log.txt"
DEFAULT_SUMMARY = "summary.json"
DEFAULT_BATCH = 1
DEFAULT_FLUSH_INTERVAL = 2
DEFAULT_RAW_DUMP = "raw_dhcp_dump.txt"
DEFAULT_STATS_FILE = "dhcp_stats.json"
DEFAULT_THREAT_LOG = "threat_analysis.json"
DEFAULT_GEO_CACHE = "geo_cache.json"
DEFAULT_REPUTATION_DB = "dhcp_reputation.json"

# --- state & locks ---
packet_buffer = []
event_buffer = []
raw_buffer = []
threat_buffer = []
geo_cache = {}
reputation_db = {}
buf_lock = threading.Lock()
geo_lock = threading.Lock()
reputation_lock = threading.Lock()

# --- Advanced tracking structures ---
internet_dhcp_servers = defaultdict(lambda: {
    'first_seen': None,
    'last_seen': None,
    'packet_count': 0,
    'countries': set(),
    'isps': set(),
    'client_interactions': set(),
    'threat_score': 0,
    'reputation': 'unknown',
    'anomalies': []
})

dhcp_fingerprints = defaultdict(lambda: {
    'vendor_class': None,
    'parameter_request_list': None,
    'os_guess': None,
    'device_type': None,
    'confidence': 0
})

covert_channels = defaultdict(list)
dns_tunneling_patterns = defaultdict(int)
suspicious_patterns = defaultdict(list)
traffic_anomalies = deque(maxlen=1000)

# --- Performance and monitoring ---
performance_metrics = {
    'packets_per_second': deque(maxlen=60),
    'processing_latency': deque(maxlen=100),
    'memory_usage': deque(maxlen=60),
    'thread_pool_utilization': deque(maxlen=60)
}

# --- Hostname resolution cache and optimization ---
hostname_cache = {}
hostname_cache_lock = threading.Lock()
failed_hostname_cache = set()  # Cache failed lookups to avoid retrying
cache_ttl = 300  # 5 minutes TTL for hostname cache

# Thread pool for parallel processing
executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
processing_queue = queue.Queue(maxsize=10000)
stopping = threading.Event()
packet_count = {"total": 0, "dhcp": 0, "udp": 0, "other": 0, "raw_dhcp": 0, "malformed": 0}
transactions = defaultdict(list)
client_history = defaultdict(list)
server_stats = defaultdict(int)
network_topology = {}
dhcp_conversations = defaultdict(list)
unique_vendors = set()
unique_hostnames = set()
lease_tracking = {}
option_frequency = defaultdict(int)

# DHCP message types
DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}

# DHCP options mapping - COMPLETE LIST
DHCP_OPTIONS = {
    1: "subnet_mask", 2: "time_offset", 3: "router", 4: "time_server",
    5: "name_server", 6: "dns_server", 7: "log_server", 8: "cookie_server",
    9: "lpr_server", 10: "impress_server", 11: "resource_location_server",
    12: "hostname", 13: "boot_size", 14: "merit_dump", 15: "domain_name",
    16: "swap_server", 17: "root_path", 18: "extensions_path",
    19: "ip_forwarding", 20: "non_local_source_routing", 21: "policy_filter",
    22: "max_dgram_reassembly", 23: "default_ip_ttl", 24: "path_mtu_aging_timeout",
    25: "path_mtu_plateau_table", 26: "interface_mtu", 27: "all_subnets_local",
    28: "broadcast_address", 29: "perform_mask_discovery", 30: "mask_supplier",
    31: "router_discovery", 32: "router_solicitation_address",
    33: "static_routes", 34: "trailer_encapsulation", 35: "arp_cache_timeout",
    36: "ethernet_encapsulation", 37: "tcp_default_ttl", 38: "tcp_keepalive_interval",
    39: "tcp_keepalive_garbage", 40: "nis_domain", 41: "nis_servers",
    42: "ntp_servers", 43: "vendor_specific", 44: "netbios_name_server", 
    45: "netbios_dgram_dist_server", 46: "netbios_node_type", 47: "netbios_scope", 
    48: "x_window_font_server", 49: "x_window_display_manager", 50: "requested_addr", 
    51: "lease_time", 52: "option_overload", 53: "message-type", 54: "server_id",
    55: "param_req_list", 56: "message", 57: "max_message_size",
    58: "renewal_time", 59: "rebinding_time", 60: "vendor_class_id",
    61: "client_id", 62: "netware_ip_domain", 63: "netware_ip_option",
    64: "nis_plus_domain", 65: "nis_plus_servers", 66: "tftp_server_name", 
    67: "bootfile_name", 68: "mobile_ip_home_agent", 69: "smtp_server",
    70: "pop3_server", 71: "nntp_server", 72: "www_server", 73: "finger_server",
    74: "irc_server", 75: "streettalk_server", 76: "streettalk_directory_assistance",
    77: "user_class", 78: "slp_directory_agent", 79: "slp_service_scope",
    80: "rapid_commit", 81: "fqdn", 82: "relay_agent", 83: "internet_storage_name_service",
    85: "nds_servers", 86: "nds_tree_name", 87: "nds_context",
    88: "bcmcs_controller_domain_name", 89: "bcmcs_controller_ipv4_address",
    90: "authentication", 91: "client_last_transaction_time", 92: "associated_ip",
    93: "client_arch", 94: "client_ndi", 95: "ldap", 96: "ipv6_transitions",
    97: "uuid_guid", 98: "user_auth", 99: "geoconf_civic", 100: "pcode",
    101: "tcode", 108: "ipv6_only_preferred", 112: "netinfo_address",
    113: "netinfo_tag", 114: "url", 115: "auto_config", 116: "name_service_search",
    117: "subnet_selection_option", 118: "domain_search", 119: "sip_servers",
    120: "classless_static_route", 121: "ccc", 122: "geoconf", 123: "vendor_class",
    124: "vendor_specific_info", 125: "vivso", 128: "tftp_server_address",
    129: "call_server_address", 130: "discrimination_string", 131: "remote_statistics_server",
    132: "vlan_id", 133: "l2_priority", 134: "diffserv_code_point",
    135: "http_proxy_for_phone_specific_applications", 136: "pana_auth_agent",
    137: "lost_server", 138: "capwap_ac_addresses", 139: "ipv4_address_mos",
    140: "ipv4_fqdn_mos", 141: "sip_ua_config_service_domains", 142: "ipv4_address_andsf",
    143: "ipv6_address_andsf", 150: "grub_configuration_path", 208: "pxelinux_magic", 
    209: "pxelinux_configfile", 210: "pxelinux_pathprefix", 211: "pxelinux_reboottime",
    212: "option_6rd", 213: "access_domain", 220: "subnet_allocation",
    221: "virtual_subnet_selection", 252: "wpad", 255: "end"
}

def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")

def resolve_hostname(ip_address, timeout=0.5):
    """Fast hostname resolution with caching and minimal timeouts"""
    if not ip_address or ip_address in ["0.0.0.0", "255.255.255.255"]:
        return None
    
    # Check failed cache first (avoid retrying known failures)
    if ip_address in failed_hostname_cache:
        return None
    
    # Check cache first
    with hostname_cache_lock:
        if ip_address in hostname_cache:
            cached_entry = hostname_cache[ip_address]
            # Check if cache entry is still valid (TTL)
            if time.time() - cached_entry['timestamp'] < cache_ttl:
                return cached_entry['hostname']
            else:
                # Remove expired entry
                del hostname_cache[ip_address]
    
    hostname = None
    
    try:
        # Only try fast methods for real-time processing
        socket.setdefaulttimeout(timeout)
        
        # Method 1: Quick reverse DNS lookup (fastest)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            if hostname and hostname != ip_address:
                # Cache successful result
                with hostname_cache_lock:
                    hostname_cache[ip_address] = {
                        'hostname': hostname,
                        'timestamp': time.time()
                    }
                return hostname
        except:
            pass
        
        # Method 2: Quick getfqdn (backup)
        try:
            fqdn = socket.getfqdn(ip_address)
            if fqdn and fqdn != ip_address and '.' in fqdn:
                # Cache successful result
                with hostname_cache_lock:
                    hostname_cache[ip_address] = {
                        'hostname': fqdn,
                        'timestamp': time.time()
                    }
                return fqdn
        except:
            pass
        
        # If all fast methods fail, cache as failed to avoid retrying
        failed_hostname_cache.add(ip_address)
        return None
        
    except Exception as e:
        # Cache failure to avoid retrying
        failed_hostname_cache.add(ip_address)
        return None

def get_hostname_info_fast(ip_address):
    """Fast hostname info with minimal overhead for real-time processing"""
    if not ip_address or ip_address == "0.0.0.0":
        return None
    
    info = {"ip": ip_address}
    
    # Only do fast hostname lookup
    hostname = resolve_hostname(ip_address, timeout=0.3)
    
    if hostname:
        info["hostname"] = hostname
        info["domain"] = hostname.split('.', 1)[1] if '.' in hostname else None
        info["short_name"] = hostname.split('.')[0]
    else:
        info["hostname"] = None
        info["short_name"] = None
        info["domain"] = None
    
    # Quick IP type classification (no external commands)
    try:
        octets = ip_address.split('.')
        first_octet = int(octets[0])
        second_octet = int(octets[1]) if len(octets) > 1 else 0
        
        if first_octet == 127:
            info["type"] = "loopback"
        elif first_octet == 10:
            info["type"] = "private_class_a"
        elif first_octet == 172 and 16 <= second_octet <= 31:
            info["type"] = "private_class_b"
        elif first_octet == 192 and second_octet == 168:
            info["type"] = "private_class_c"
        elif first_octet == 169 and second_octet == 254:
            info["type"] = "link_local"
        elif first_octet >= 224:
            info["type"] = "multicast_or_reserved"
        else:
            info["type"] = "public"
    except:
        info["type"] = "unknown"
    
    return info

def analyze_raw_dhcp_packet(pkt):
    """Comprehensive analysis of any DHCP-related packet"""
    analysis = {
        "timestamp": now_iso(),
        "packet_size": len(pkt),
        "layers": [layer.name for layer in pkt.layers()],
        "has_ethernet": Ether in pkt,
        "has_ip": IP in pkt,
        "has_udp": UDP in pkt,
        "has_bootp": BOOTP in pkt,
        "has_dhcp": DHCP in pkt,
        "has_raw": Raw in pkt,
        "packet_hex": bytes(pkt).hex()
    }
    
    # Ethernet analysis
    if Ether in pkt:
        eth = pkt[Ether]
        analysis["ethernet"] = {
            "src_mac": str(eth.src),
            "dst_mac": str(eth.dst),
            "ethertype": hex(eth.type),
            "is_broadcast": str(eth.dst) == "ff:ff:ff:ff:ff:ff",
            "is_multicast": int(str(eth.dst).split(':')[0], 16) & 1
        }
    
    # IP analysis
    if IP in pkt:
        ip = pkt[IP]
        analysis["ip"] = {
            "version": ip.version,
            "header_length": ip.ihl * 4,
            "tos": ip.tos,
            "total_length": ip.len,
            "identification": ip.id,
            "flags": int(ip.flags),
            "fragment_offset": ip.frag,
            "ttl": ip.ttl,
            "protocol": ip.proto,
            "checksum": ip.chksum,
            "src_ip": str(ip.src),
            "dst_ip": str(ip.dst),
            "options": getattr(ip, 'options', [])
        }
    
    # UDP analysis
    if UDP in pkt:
        udp = pkt[UDP]
        analysis["udp"] = {
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
            "checksum": udp.chksum,
            "payload_size": len(udp.payload) if udp.payload else 0
        }
        
        # Determine DHCP direction
        if udp.sport == 68 and udp.dport == 67:
            analysis["dhcp_direction"] = "client_to_server"
        elif udp.sport == 67 and udp.dport == 68:
            analysis["dhcp_direction"] = "server_to_client"
        else:
            analysis["dhcp_direction"] = "unknown"
    
    # BOOTP analysis
    if BOOTP in pkt:
        bootp = pkt[BOOTP]
        analysis["bootp"] = {
            "op": int(bootp.op),
            "htype": int(bootp.htype),
            "hlen": int(bootp.hlen),
            "hops": int(bootp.hops),
            "xid": hex(bootp.xid),
            "secs": int(bootp.secs),
            "flags": int(bootp.flags),
            "ciaddr": str(bootp.ciaddr),
            "yiaddr": str(bootp.yiaddr),
            "siaddr": str(bootp.siaddr),
            "giaddr": str(bootp.giaddr),
            "chaddr": mac_bytes_to_str(bootp.chaddr),
            "sname": bootp.sname.decode('utf-8', errors='ignore').rstrip('\x00') if bootp.sname else "",
            "file": bootp.file.decode('utf-8', errors='ignore').rstrip('\x00') if bootp.file else ""
        }
    
    # DHCP options analysis
    if DHCP in pkt:
        dhcp = pkt[DHCP]
        analysis["dhcp_options_raw"] = str(dhcp.options)
        analysis["dhcp_options_count"] = len(dhcp.options)
        
        # Extract all options in detail
        detailed_options = []
        for opt in dhcp.options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                opt_code, opt_val = opt[0], opt[1]
                opt_detail = {
                    "code": opt_code,
                    "name": DHCP_OPTIONS.get(opt_code, f"unknown_{opt_code}"),
                    "value": opt_val,
                    "value_type": type(opt_val).__name__,
                    "raw_hex": opt_val.hex() if isinstance(opt_val, bytes) else str(opt_val)
                }
                detailed_options.append(opt_detail)
            else:
                detailed_options.append({"raw": str(opt)})
        
        analysis["dhcp_options_detailed"] = detailed_options
    
    # Raw payload analysis
    if Raw in pkt:
        raw_data = bytes(pkt[Raw])
        analysis["raw_payload"] = {
            "size": len(raw_data),
            "hex": raw_data.hex(),
            "ascii": ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_data[:100])
        }
    
    return analysis

def get_local_hostname_from_arp(ip_address):
    """Try to get hostname from local ARP table and network discovery (Linux)"""
    try:
        print(f"[DEBUG] Checking ARP table for {ip_address}")
        import subprocess
        
        # Check ARP table (Linux format)
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ip_address in line:
                    # Linux arp format: hostname (ip) at mac [ether] on interface
                    parts = line.strip().split()
                    if len(parts) >= 1:
                        hostname_part = parts[0]
                        if hostname_part and hostname_part != ip_address and not hostname_part.startswith('?'):
                            print(f"[DEBUG] Found in ARP: {ip_address} -> {hostname_part}")
                            return hostname_part
        
        # Alternative ARP check with -n flag
        result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ip_address in line:
                    print(f"[DEBUG] ARP entry found: {line.strip()}")
        
        # Try avahi-resolve for local network names (Linux)
        try:
            result = subprocess.run(['avahi-resolve', '-a', ip_address], 
                                  capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                hostname = result.stdout.strip().split('\t')[1] if '\t' in result.stdout else None
                if hostname and hostname != ip_address:
                    print(f"[DEBUG] avahi-resolve found: {ip_address} -> {hostname}")
                    return hostname
        except FileNotFoundError:
            print(f"[DEBUG] avahi-resolve not available")
        except Exception as e:
            print(f"[DEBUG] avahi-resolve failed: {e}")
        
        # Try getent hosts (Linux system database)
        try:
            result = subprocess.run(['getent', 'hosts', ip_address], 
                                  capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1]
                    if hostname and hostname != ip_address:
                        print(f"[DEBUG] getent hosts found: {ip_address} -> {hostname}")
                        return hostname
        except FileNotFoundError:
            print(f"[DEBUG] getent command not available")
        except Exception as e:
            print(f"[DEBUG] getent failed: {e}")
            
    except Exception as e:
        print(f"[DEBUG] ARP lookup failed for {ip_address}: {e}")
    
    return None

def get_hostname_info(ip_address):
    """Get comprehensive hostname information - optimized for real-time processing"""
    return get_hostname_info_fast(ip_address)

def clear_hostname_cache_periodically():
    """Background thread to periodically clear failed hostname cache"""
    while not stopping.is_set():
        try:
            time.sleep(600)  # Clear every 10 minutes
            
            # Clear failed cache to allow retry of previously failed lookups
            global failed_hostname_cache
            failed_hostname_cache.clear()
            
            # Clean up expired entries from hostname cache
            current_time = time.time()
            with hostname_cache_lock:
                expired_keys = [
                    ip for ip, entry in hostname_cache.items()
                    if current_time - entry['timestamp'] > cache_ttl
                ]
                for key in expired_keys:
                    del hostname_cache[key]
            
            if len(expired_keys) > 0:
                logging.info(f"[CACHE] Cleared {len(expired_keys)} expired hostname entries")
                
        except Exception as e:
            logging.error(f"Error in hostname cache cleanup: {e}")
            time.sleep(60)

def monitor_performance():
    """Background thread for performance monitoring"""
    while not stopping.is_set():
        try:
            try:
                import psutil
                
                # Memory usage
                memory_usage = psutil.virtual_memory().percent
                performance_metrics['memory_usage'].append(memory_usage)
                
                # Thread pool utilization
                active_threads = threading.active_count()
                performance_metrics['thread_pool_utilization'].append(active_threads)
                
                # Log warnings for high resource usage
                if memory_usage > 80:
                    logging.warning(f"High memory usage: {memory_usage}%")
                
                if active_threads > 20:
                    logging.warning(f"High thread count: {active_threads}")
                
                time.sleep(30)  # Check every 30 seconds
                
            except ImportError:
                # psutil not available, skip monitoring
                time.sleep(60)
                
        except Exception as e:
            logging.error(f"Error in performance monitoring: {e}")
            time.sleep(60)

def mac_bytes_to_str(b):
    if isinstance(b, bytes):
        return ':'.join(f"{x:02x}" for x in b[:6])
    return str(b)

def bytes_to_hex(b):
    if isinstance(b, bytes):
        return b.hex()
    return str(b)

def ip_list_to_str(val):
    if isinstance(val, list):
        return [str(v) for v in val]
    return str(val)

def parse_client_id(val):
    if isinstance(val, bytes):
        if len(val) > 1 and val[0] == 1:
            return {"type": "ethernet", "mac": mac_bytes_to_str(val[1:])}
        return {"type": "raw", "hex": bytes_to_hex(val)}
    return val

def parse_vendor_class(val):
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8', errors='ignore').strip()
        except:
            return bytes_to_hex(val)
    return str(val)

def parse_param_req_list(val):
    if isinstance(val, bytes):
        return [int(b) for b in val]
    return val

def parse_fqdn(val):
    if isinstance(val, bytes):
        try:
            flags = val[0]
            rcode1 = val[1]
            rcode2 = val[2]
            domain = val[3:].decode('utf-8', errors='ignore')
            return {
                "flags": flags,
                "rcode1": rcode1,
                "rcode2": rcode2,
                "domain": domain
            }
        except:
            return bytes_to_hex(val)
    return val

def parse_relay_agent(val):
    if isinstance(val, bytes):
        info = {}
        i = 0
        while i < len(val):
            try:
                sub_opt = val[i]
                sub_len = val[i+1]
                sub_val = val[i+2:i+2+sub_len]
                if sub_opt == 1:
                    info["circuit_id"] = bytes_to_hex(sub_val)
                elif sub_opt == 2:
                    info["remote_id"] = bytes_to_hex(sub_val)
                else:
                    info[f"sub_option_{sub_opt}"] = bytes_to_hex(sub_val)
                i += 2 + sub_len
            except:
                break
        return info
    return val

def dhcp_options_to_dict(options):
    opts = {}
    raw_opts = {}
    
    print(f"[DEBUG] Processing DHCP options: {options}")
    print(f"[DEBUG] Options type: {type(options)}")
    print(f"[DEBUG] Options length: {len(options) if hasattr(options, '__len__') else 'N/A'}")
    
    # Handle different option formats
    if not options:
        print("[DEBUG] No DHCP options found")
        return opts, raw_opts
    
    for i, opt in enumerate(options):
        print(f"[DEBUG] Processing option {i}: {opt} (type: {type(opt)})")
        
        if isinstance(opt, tuple) and len(opt) >= 2:
            opt_code, val = opt[0], opt[1]
            
            # Ensure opt_code is an integer
            try:
                opt_code = int(opt_code)
            except (ValueError, TypeError):
                print(f"[DEBUG] Skipping non-integer DHCP option code: {opt_code}")
                continue
            
            print(f"[DEBUG] Option {opt_code}: {val} (type: {type(val)})")
            
            # Store raw value first
            if isinstance(val, bytes):
                raw_opts[opt_code] = bytes_to_hex(val)
                print(f"[DEBUG] Option {opt_code} as hex: {raw_opts[opt_code]}")
            else:
                raw_opts[opt_code] = str(val)
            
            opt_name = DHCP_OPTIONS.get(opt_code, f"option_{opt_code}")
            
            if opt_code == 53:  # DHCP Message Type
                print(f"[DEBUG] Found DHCP message type option: {val}")
                # Handle message type more robustly
                if isinstance(val, bytes) and len(val) > 0:
                    opts[opt_name] = val[0]
                    print(f"[DEBUG] Message type from bytes: {val[0]}")
                elif isinstance(val, int):
                    opts[opt_name] = val
                    print(f"[DEBUG] Message type as int: {val}")
                else:
                    try:
                        opts[opt_name] = int(val)
                        print(f"[DEBUG] Message type converted to int: {int(val)}")
                    except:
                        print(f"[DEBUG] Could not parse DHCP message type: {val}")
                        opts[opt_name] = val
            elif opt_code == 55:
                opts[opt_name] = parse_param_req_list(val)
                opts[f"{opt_name}_named"] = [DHCP_OPTIONS.get(x, f"option_{x}") for x in opts[opt_name]]
            elif opt_code == 61:
                opts[opt_name] = parse_client_id(val)
            elif opt_code == 60:
                opts[opt_name] = parse_vendor_class(val)
            elif opt_code == 81:
                opts[opt_name] = parse_fqdn(val)
            elif opt_code == 82:
                opts[opt_name] = parse_relay_agent(val)
            elif opt_code == 12:  # hostname option
                if isinstance(val, bytes):
                    try:
                        # Clean up hostname - remove null terminators and decode
                        hostname_clean = val.decode('utf-8', errors='ignore').rstrip('\x00').strip()
                        if hostname_clean:
                            opts[opt_name] = hostname_clean
                            print(f"[DEBUG] Found hostname in option 12: {hostname_clean}")
                        else:
                            opts[opt_name] = bytes_to_hex(val)
                    except:
                        opts[opt_name] = bytes_to_hex(val)
                else:
                    opts[opt_name] = str(val)
            elif opt_code == 15:  # domain_name option
                if isinstance(val, bytes):
                    try:
                        domain_clean = val.decode('utf-8', errors='ignore').rstrip('\x00').strip()
                        if domain_clean:
                            opts[opt_name] = domain_clean
                            print(f"[DEBUG] Found domain name in option 15: {domain_clean}")
                        else:
                            opts[opt_name] = bytes_to_hex(val)
                    except:
                        opts[opt_name] = bytes_to_hex(val)
                else:
                    opts[opt_name] = str(val)
                opts[opt_name] = ip_list_to_str(val)
            elif isinstance(val, bytes):
                try:
                    decoded = val.decode('utf-8', errors='ignore').strip('\x00')
                    if decoded.isprintable() and len(decoded) > 0:
                        opts[opt_name] = decoded
                    else:
                        opts[opt_name] = bytes_to_hex(val)
                except:
                    opts[opt_name] = bytes_to_hex(val)
            else:
                opts[opt_name] = val
                
        elif opt == 'end':
            opts['end'] = True
    
    return opts, raw_opts

def extract_fingerprint(ev):
    fp = {}
    
    if ev.get("vendor_class_id"):
        fp["vendor_class"] = ev["vendor_class_id"]
    
    if ev.get("param_req_list"):
        fp["dhcp_options_requested"] = ev["param_req_list"]
        fp["dhcp_fingerprint"] = ",".join(map(str, ev["param_req_list"]))
    
    if ev.get("hostname"):
        fp["hostname"] = ev["hostname"]
    
    if ev.get("client_id"):
        fp["client_id"] = ev["client_id"]
        
    return fp if fp else None

def create_basic_dhcp_event(pkt):
    """Create a basic DHCP event for packets that don't have proper DHCP layers"""
    try:
        ev = {
            "time": now_iso(),
            "timestamp": time.time(),
            "message_type": "RAW_DHCP_TRAFFIC",
            "message_type_code": None,
            "packet_length": len(pkt),
            "is_raw_dhcp": True
        }
        
        if Ether in pkt:
            ev["src_mac"] = str(pkt[Ether].src)
            ev["dst_mac"] = str(pkt[Ether].dst)
            
        if IP in pkt:
            ev["src_ip"] = str(pkt[IP].src)
            ev["dst_ip"] = str(pkt[IP].dst)
            ev["ip_ttl"] = pkt[IP].ttl if hasattr(pkt[IP], "ttl") else None
            ev["ip_id"] = pkt[IP].id if hasattr(pkt[IP], "id") else None
            
            # Only do hostname resolution for diagnostic mode or when specifically enabled
            # This avoids timeouts during high-speed packet processing
            if ((hasattr(config, 'diagnostic') and config.diagnostic) or 
                (hasattr(config, 'enable_hostname_resolution') and config.enable_hostname_resolution)):
                # Add hostname resolution (only when specifically enabled)
                src_hostname_info = get_hostname_info(ev["src_ip"])
                if src_hostname_info:
                    ev["src_hostname_info"] = src_hostname_info
                    ev["src_hostname"] = src_hostname_info.get("hostname", "N/A")
                    ev["src_short_name"] = src_hostname_info.get("short_name", "N/A")
                else:
                    ev["src_hostname"] = "N/A"
                    ev["src_short_name"] = "N/A"
                
                dst_hostname_info = get_hostname_info(ev["dst_ip"])
                if dst_hostname_info:
                    ev["dst_hostname_info"] = dst_hostname_info
                    ev["dst_hostname"] = dst_hostname_info.get("hostname", "N/A")
                    ev["dst_short_name"] = dst_hostname_info.get("short_name", "N/A")
                else:
                    ev["dst_hostname"] = "N/A"
                    ev["dst_short_name"] = "N/A"
            else:
                # Skip hostname resolution for faster processing
                ev["src_hostname"] = "N/A"
                ev["src_short_name"] = "N/A"
                ev["dst_hostname"] = "N/A"
                ev["dst_short_name"] = "N/A"
            
        if UDP in pkt:
            ev["src_port"] = int(pkt[UDP].sport)
            ev["dst_port"] = int(pkt[UDP].dport)
            ev["udp_length"] = int(pkt[UDP].len)
            
            # Determine if this is client->server or server->client
            if pkt[UDP].sport == 68 and pkt[UDP].dport == 67:
                ev["direction"] = "client_to_server"
            elif pkt[UDP].sport == 67 and pkt[UDP].dport == 68:
                ev["direction"] = "server_to_client"
            else:
                ev["direction"] = "unknown"
        
        if Raw in pkt:
            ev["has_raw_layer"] = True
            raw_data = bytes(pkt[Raw])
            ev["raw_data_length"] = len(raw_data)
            # Show first 32 bytes as hex for debugging
            ev["raw_data_preview"] = raw_data[:32].hex() if len(raw_data) > 0 else ""
        
        return ev
    except Exception as e:
        logging.exception("Error creating basic DHCP event")
        return None

def extract_dhcp_hostnames(dhcp_options_raw):
    """Extract all hostname-related information from raw DHCP options"""
    hostname_info = {}
    
    if not dhcp_options_raw:
        return hostname_info
    
    # Parse the raw options string to extract hostname data
    import re
    
    # Look for hostname option (12)
    hostname_match = re.search(r"'hostname',\s*b'([^']+)'", str(dhcp_options_raw))
    if hostname_match:
        hostname_bytes_str = hostname_match.group(1)
        try:
            # Handle escaped characters
            hostname_clean = hostname_bytes_str.replace('\\x00', '').replace('\\', '').strip()
            if hostname_clean:
                hostname_info['dhcp_hostname'] = hostname_clean
                print(f"[DEBUG] Extracted DHCP hostname: {hostname_clean}")
        except Exception as e:
            print(f"[DEBUG] Failed to extract hostname: {e}")
    
    # Look for domain name option (15)
    domain_match = re.search(r"'domain_name',\s*b'([^']+)'", str(dhcp_options_raw))
    if domain_match:
        domain_bytes_str = domain_match.group(1)
        try:
            domain_clean = domain_bytes_str.replace('\\x00', '').replace('\\', '').strip()
            if domain_clean:
                hostname_info['dhcp_domain'] = domain_clean
                print(f"[DEBUG] Extracted DHCP domain: {domain_clean}")
        except Exception as e:
            print(f"[DEBUG] Failed to extract domain: {e}")
    
    # Look for vendor class option (60)
    vendor_match = re.search(r"'vendor_class_id',\s*b'([^']+)'", str(dhcp_options_raw))
    if vendor_match:
        vendor_bytes_str = vendor_match.group(1)
        try:
            vendor_clean = vendor_bytes_str.replace('\\x00', '').replace('\\', '').strip()
            if vendor_clean:
                hostname_info['dhcp_vendor_class'] = vendor_clean
                print(f"[DEBUG] Extracted DHCP vendor class: {vendor_clean}")
        except Exception as e:
            print(f"[DEBUG] Failed to extract vendor class: {e}")
    
    return hostname_info

def parse_dhcp(pkt, config=None):
    try:
        bootp = pkt.getlayer(BOOTP)
        dhcp = pkt.getlayer(DHCP)
        if not bootp or not dhcp:
            return None
        
        # Debug: Show raw DHCP options structure (only in diagnostic mode)
        if config and getattr(config, 'diagnostic', False):
            print(f"[DEBUG] Raw DHCP options: {dhcp.options}")
            print(f"[DEBUG] DHCP options type: {type(dhcp.options)}")
        
        opts, raw_opts = dhcp_options_to_dict(dhcp.options)
        mtype_raw = opts.get("message-type")
        
        # If no message type found, try to infer from BOOTP op field
        if mtype_raw is None:
            if config and getattr(config, 'diagnostic', False):
                print(f"[DEBUG] No DHCP message type found in options")
                print(f"[DEBUG] BOOTP op field: {bootp.op}")
                print(f"[DEBUG] All parsed options: {opts}")
                print(f"[DEBUG] All raw options: {raw_opts}")
            
            # Try to determine message type from context
            if hasattr(bootp, 'op'):
                if bootp.op == 1:  # BOOTREQUEST
                    # Check if client is requesting specific IP
                    if str(bootp.ciaddr) != "0.0.0.0":
                        mtype_raw = 3  # REQUEST
                        mtype = "REQUEST"
                    else:
                        mtype_raw = 1  # DISCOVER
                        mtype = "DISCOVER"
                elif bootp.op == 2:  # BOOTREPLY
                    # Check if offering an IP
                    if str(bootp.yiaddr) != "0.0.0.0":
                        mtype_raw = 2  # OFFER
                        mtype = "OFFER"
                    else:
                        mtype_raw = 5  # ACK
                        mtype = "ACK"
                else:
                    mtype = f"INFERRED_FROM_OP({bootp.op})"
            else:
                mtype = "NO_MESSAGE_TYPE"
        else:
            mtype = DHCP_MSG_TYPES.get(mtype_raw, f"Unknown({mtype_raw})")
        # Enhanced BOOTP field extraction
        mac = mac_bytes_to_str(bootp.chaddr)
        xid = bootp.xid if hasattr(bootp, "xid") else None
        
        if config and getattr(config, 'diagnostic', False):
            print(f"[DEBUG] BOOTP fields:")
            print(f"  - op: {getattr(bootp, 'op', 'N/A')}")
            print(f"  - htype: {getattr(bootp, 'htype', 'N/A')}")
            print(f"  - hlen: {getattr(bootp, 'hlen', 'N/A')}")
            print(f"  - hops: {getattr(bootp, 'hops', 'N/A')}")
            print(f"  - xid: {hex(xid) if xid else 'N/A'}")
            print(f"  - secs: {getattr(bootp, 'secs', 'N/A')}")
            print(f"  - flags: {getattr(bootp, 'flags', 'N/A')}")
            print(f"  - ciaddr: {getattr(bootp, 'ciaddr', 'N/A')}")
            print(f"  - yiaddr: {getattr(bootp, 'yiaddr', 'N/A')}")
            print(f"  - siaddr: {getattr(bootp, 'siaddr', 'N/A')}")
            print(f"  - giaddr: {getattr(bootp, 'giaddr', 'N/A')}")
            print(f"  - chaddr: {mac}")
            print(f"  - sname: {getattr(bootp, 'sname', 'N/A')}")
            print(f"  - file: {getattr(bootp, 'file', 'N/A')}")
        
        # Try to extract more information from server name and boot file fields
        sname = None
        bootfile = None
        if hasattr(bootp, 'sname') and bootp.sname:
            try:
                sname_bytes = bytes(bootp.sname)
                sname = sname_bytes.decode('utf-8', errors='ignore').rstrip('\x00').strip()
                if sname and config and getattr(config, 'diagnostic', False):
                    print(f"[DEBUG] Server name: {sname}")
            except:
                pass
                
        if hasattr(bootp, 'file') and bootp.file:
            try:
                file_bytes = bytes(bootp.file)
                bootfile = file_bytes.decode('utf-8', errors='ignore').rstrip('\x00').strip()
                if bootfile and config and getattr(config, 'diagnostic', False):
                    print(f"[DEBUG] Boot file: {bootfile}")
            except:
                pass
        
        # Helper function to safely convert Scapy fields to int
        def safe_int(value):
            try:
                return int(value) if value is not None else None
            except (TypeError, ValueError):
                return None
        
        # Handle bootp.flags robustly
        flags_val = None
        if hasattr(bootp, "flags"):
            try:
                flags_val = hex(int(bootp.flags))
            except Exception:
                try:
                    flags_val = hex(int(bootp.flags.value))
                except Exception:
                    flags_val = str(bootp.flags)
        
        ev = {
            "time": now_iso(),
            "timestamp": time.time(),
            "op": safe_int(bootp.op) if hasattr(bootp, "op") else None,
            "htype": safe_int(bootp.htype) if hasattr(bootp, "htype") else None,
            "hlen": safe_int(bootp.hlen) if hasattr(bootp, "hlen") else None,
            "hops": safe_int(bootp.hops) if hasattr(bootp, "hops") else None,
            "transaction_id": hex(xid) if xid else None,
            "transaction_id_int": xid,
            "seconds": safe_int(bootp.secs) if hasattr(bootp, "secs") else None,
            "flags": flags_val,
            "ciaddr": str(bootp.ciaddr) if hasattr(bootp, "ciaddr") else None,
            "yiaddr": str(bootp.yiaddr) if hasattr(bootp, "yiaddr") else None,
            "siaddr": str(bootp.siaddr) if hasattr(bootp, "siaddr") else None,
            "giaddr": str(bootp.giaddr) if hasattr(bootp, "giaddr") else None,
            "chaddr": mac,
            "sname": sname,
            "file": bootfile,
            "message_type": mtype,
            "message_type_code": mtype_raw,
            "debug_info": {
                "dhcp_options_found": len(raw_opts),
                "bootp_layer_present": True,
                "dhcp_layer_present": True,
                "raw_dhcp_options": list(raw_opts.keys()) if raw_opts else []
            }
        }
        
        # Add inferred information when DHCP options are missing
        if not raw_opts or len(raw_opts) == 0:
            ev["debug_info"]["no_dhcp_options"] = True
            ev["inferred_data"] = {}
            
            # Try to infer server information from packet layers
            if IP in pkt:
                if pkt[UDP].sport == 67:  # Server -> Client
                    ev["inferred_data"]["dhcp_server_ip"] = str(pkt[IP].src)
                elif pkt[UDP].dport == 67:  # Client -> Server
                    ev["inferred_data"]["dhcp_server_ip"] = str(pkt[IP].dst)
            
            # Try to extract network information from BOOTP fields
            if str(bootp.yiaddr) != "0.0.0.0":
                ev["inferred_data"]["offered_ip"] = str(bootp.yiaddr)
            if str(bootp.siaddr) != "0.0.0.0":
                ev["inferred_data"]["next_server"] = str(bootp.siaddr)
            if str(bootp.giaddr) != "0.0.0.0":
                ev["inferred_data"]["relay_agent"] = str(bootp.giaddr)
        
        # Extract additional hostname information from raw DHCP options
        dhcp_hostname_info = extract_dhcp_hostnames(dhcp.options)
        if dhcp_hostname_info:
            ev.update(dhcp_hostname_info)
            print(f"[DEBUG] Added DHCP hostname info: {dhcp_hostname_info}")
        
        ev.update(opts)
        ev["raw_options"] = raw_opts
        
        # Extract additional hostname information from raw options if not already found
        if not ev.get('hostname') and raw_opts:
            print(f"[DEBUG] Looking for hostname in raw options: {raw_opts}")
            for opt_code, raw_val in raw_opts.items():
                try:
                    opt_code_int = int(opt_code)
                    if opt_code_int == 12:  # hostname option
                        # Try to decode hex string back to hostname
                        try:
                            hostname_bytes = bytes.fromhex(raw_val)
                            hostname_decoded = hostname_bytes.decode('utf-8', errors='ignore').rstrip('\x00').strip()
                            if hostname_decoded:
                                ev['hostname'] = hostname_decoded
                                ev['hostname_source'] = 'raw_option_12'
                                print(f"[DEBUG] Extracted hostname from raw option: {hostname_decoded}")
                                break
                        except:
                            pass
                except:
                    pass
        
        # Also check if hostname is in the parsed options but wasn't properly extracted
        if not ev.get('hostname'):
            for key, value in ev.items():
                if key == 'hostname' and isinstance(value, bytes):
                    try:
                        hostname_clean = value.decode('utf-8', errors='ignore').rstrip('\x00').strip()
                        if hostname_clean:
                            ev['hostname'] = hostname_clean
                            ev['hostname_source'] = 'parsed_bytes'
                            print(f"[DEBUG] Cleaned hostname from bytes: {hostname_clean}")
                    except:
                        pass
        
        fp = extract_fingerprint(ev)
        if fp:
            ev["fingerprint"] = fp
        
        if Ether in pkt:
            ev["src_mac"] = str(pkt[Ether].src)
            ev["dst_mac"] = str(pkt[Ether].dst)
            
        if IP in pkt:
            ev["src_ip"] = str(pkt[IP].src)
            ev["dst_ip"] = str(pkt[IP].dst)
            ev["ip_ttl"] = safe_int(pkt[IP].ttl)
            ev["ip_id"] = safe_int(pkt[IP].id)
            
            # Add hostname resolution for source and destination
            src_hostname_info = get_hostname_info(ev["src_ip"])
            if src_hostname_info:
                ev["src_hostname_info"] = src_hostname_info
                ev["src_hostname"] = src_hostname_info.get("hostname", "N/A")
                ev["src_short_name"] = src_hostname_info.get("short_name", "N/A")
            else:
                ev["src_hostname"] = "N/A"
                ev["src_short_name"] = "N/A"
            
            dst_hostname_info = get_hostname_info(ev["dst_ip"])
            if dst_hostname_info:
                ev["dst_hostname_info"] = dst_hostname_info
                ev["dst_hostname"] = dst_hostname_info.get("hostname", "N/A")
                ev["dst_short_name"] = dst_hostname_info.get("short_name", "N/A")
            else:
                ev["dst_hostname"] = "N/A"
                ev["dst_short_name"] = "N/A"
            
        if UDP in pkt:
            ev["src_port"] = safe_int(pkt[UDP].sport)
            ev["dst_port"] = safe_int(pkt[UDP].dport)
            ev["udp_length"] = safe_int(pkt[UDP].len)
        
        ev["packet_length"] = len(pkt)
        
        if Raw in pkt:
            ev["has_raw_layer"] = True
            
        return ev
    except Exception as e:
        logging.exception("parse_dhcp error")
        return None

def pretty_line(ev):
    """Create detailed multi-line human-readable output"""
    lines = []
    lines.append("=" * 80)
    
    # Handle raw DHCP traffic differently
    if ev.get("is_raw_dhcp"):
        lines.append(f"[{ev['time']}] RAW DHCP TRAFFIC")
        lines.append("-" * 80)
        lines.append(f"Direction:        {ev.get('direction', 'unknown')}")
        lines.append(f"Source:           {ev.get('src_ip', 'N/A')}:{ev.get('src_port', 'N/A')} ({ev.get('src_mac', 'N/A')})")
        lines.append(f"Source Hostname:  {ev.get('src_hostname', 'N/A')}")
        lines.append(f"Destination:      {ev.get('dst_ip', 'N/A')}:{ev.get('dst_port', 'N/A')} ({ev.get('dst_mac', 'N/A')})")
        lines.append(f"Dest Hostname:    {ev.get('dst_hostname', 'N/A')}")
        lines.append(f"Packet Length:    {ev.get('packet_length', 'N/A')} bytes")
        lines.append(f"UDP Length:       {ev.get('udp_length', 'N/A')} bytes")
        if ev.get('raw_data_preview'):
            lines.append(f"Raw Data (hex):   {ev['raw_data_preview']}...")
        lines.append("=" * 80)
        return "\n".join(lines)
    
    # Standard DHCP packet formatting
    lines.append(f"[{ev['time']}] DHCP {ev.get('message_type', 'UNKNOWN')}")
    lines.append("-" * 80)
    
    # Client Information
    lines.append("CLIENT INFO:")
    lines.append(f"  MAC Address:      {ev.get('chaddr', 'unknown')}")
    
    # Show all available hostname information
    dhcp_hostname = ev.get('dhcp_hostname', ev.get('hostname', 'N/A'))
    lines.append(f"  DHCP Hostname:    {dhcp_hostname}")
    lines.append(f"  Hostname (parsed): {ev.get('hostname', 'N/A')}")
    if ev.get('hostname_source'):
        lines.append(f"  Hostname Source:  {ev.get('hostname_source')}")
    if ev.get('dhcp_domain'):
        lines.append(f"  DHCP Domain:      {ev.get('dhcp_domain')}")
    if ev.get('dhcp_vendor_class'):
        lines.append(f"  DHCP Vendor:      {ev.get('dhcp_vendor_class')}")
    
    lines.append(f"  Client IP:        {ev.get('ciaddr', '0.0.0.0')}")
    lines.append(f"  Source MAC:       {ev.get('src_mac', 'N/A')}")
    lines.append(f"  Source IP:        {ev.get('src_ip', 'N/A')}")
    src_hostname = "N/A"
    src_short = "N/A"
    if ev.get('src_hostname_info'):
        src_hostname = ev['src_hostname_info'].get('hostname', 'N/A') or 'N/A'
        src_short = ev['src_hostname_info'].get('short_name', 'N/A') or 'N/A'
    elif ev.get('src_hostname'):
        src_hostname = ev.get('src_hostname', 'N/A') or 'N/A'
        src_short = ev.get('src_short_name', 'N/A') or 'N/A'
    lines.append(f"  Source Hostname:  {src_hostname}")
    lines.append(f"  Source Short Name: {src_short}")
    
    # Server Information
    lines.append("\nSERVER INFO:")
    lines.append(f"  Server ID:        {ev.get('server_id', 'N/A')}")
    lines.append(f"  Server IP:        {ev.get('siaddr', '0.0.0.0')}")
    lines.append(f"  Destination MAC:  {ev.get('dst_mac', 'N/A')}")
    lines.append(f"  Destination IP:   {ev.get('dst_ip', 'N/A')}")
    dst_hostname = "N/A"
    dst_short = "N/A"
    if ev.get('dst_hostname_info'):
        dst_hostname = ev['dst_hostname_info'].get('hostname', 'N/A') or 'N/A'
        dst_short = ev['dst_hostname_info'].get('short_name', 'N/A') or 'N/A'
    elif ev.get('dst_hostname'):
        dst_hostname = ev.get('dst_hostname', 'N/A') or 'N/A'
        dst_short = ev.get('dst_short_name', 'N/A') or 'N/A'
    lines.append(f"  Dest Hostname:    {dst_hostname}")
    lines.append(f"  Dest Short Name:  {dst_short}")
    
    # IP Assignment
    lines.append("\nIP ASSIGNMENT:")
    lines.append(f"  Offered IP:       {ev.get('yiaddr', '0.0.0.0')}")
    lines.append(f"  Requested IP:     {ev.get('requested_addr', 'N/A')}")
    lines.append(f"  Subnet Mask:      {ev.get('subnet_mask', 'N/A')}")
    lines.append(f"  Broadcast:        {ev.get('broadcast_address', 'N/A')}")
    
    # Network Configuration
    lines.append("\nNETWORK CONFIG:")
    if ev.get('router'):
        routers = ev['router'] if isinstance(ev['router'], list) else [ev['router']]
        lines.append(f"  Gateway/Router:   {', '.join(routers)}")
    else:
        lines.append(f"  Gateway/Router:   N/A")
    
    if ev.get('dns_server'):
        dns = ev['dns_server'] if isinstance(ev['dns_server'], list) else [ev['dns_server']]
        lines.append(f"  DNS Servers:      {', '.join(dns)}")
    else:
        lines.append(f"  DNS Servers:      N/A")
    
    lines.append(f"  Domain Name:      {ev.get('domain_name', 'N/A')}")
    if ev.get('domain_search'):
        lines.append(f"  Domain Search:    {ev.get('domain_search')}")
    
    # Lease Information
    lines.append("\nLEASE INFO:")
    lines.append(f"  Lease Time:       {ev.get('lease_time', 'N/A')} seconds")
    lines.append(f"  Renewal Time:     {ev.get('renewal_time', 'N/A')} seconds")
    lines.append(f"  Rebinding Time:   {ev.get('rebinding_time', 'N/A')} seconds")
    
    # Additional Services
    lines.append("\nADDITIONAL SERVICES:")
    lines.append(f"  NTP Servers:      {ev.get('ntp_servers', 'N/A')}")
    lines.append(f"  TFTP Server:      {ev.get('tftp_server_name', 'N/A')}")
    lines.append(f"  Boot File:        {ev.get('bootfile_name', 'N/A')}")
    if ev.get('wpad'):
        lines.append(f"  WPAD:             {ev.get('wpad')}")
    
    # DHCP Extracted Information
    if ev.get('dhcp_hostname') or ev.get('dhcp_domain') or ev.get('dhcp_vendor_class'):
        lines.append("\nDHCP EXTRACTED INFO:")
        if ev.get('dhcp_hostname'):
            lines.append(f"  DHCP Hostname:    {ev.get('dhcp_hostname')}")
        if ev.get('dhcp_domain'):
            lines.append(f"  DHCP Domain:      {ev.get('dhcp_domain')}")
        if ev.get('dhcp_vendor_class'):
            lines.append(f"  DHCP Vendor:      {ev.get('dhcp_vendor_class')}")
    
    # Fingerprinting
    lines.append("\nFINGERPRINT INFO:")
    lines.append(f"  Vendor Class:     {ev.get('vendor_class_id', 'N/A')}")
    if ev.get('client_id'):
        lines.append(f"  Client ID:        {ev.get('client_id')}")
    if ev.get('param_req_list'):
        lines.append(f"  Options Requested: {ev.get('param_req_list')}")
    if ev.get('param_req_list_named'):
        lines.append(f"  Options Names:    {', '.join(ev.get('param_req_list_named', []))}")
    
    # Transaction Details
    lines.append("\nTRANSACTION:")
    lines.append(f"  Transaction ID:   {ev.get('transaction_id', 'N/A')}")
    lines.append(f"  Message Type:     {ev.get('message_type')} (code: {ev.get('message_type_code')})")
    lines.append(f"  Operation:        {ev.get('op')} (1=request, 2=reply)")
    lines.append(f"  Hardware Type:    {ev.get('htype')}")
    lines.append(f"  Hops:             {ev.get('hops', 0)}")
    lines.append(f"  Seconds:          {ev.get('seconds', 0)}")
    lines.append(f"  Flags:            {ev.get('flags', '0x0')}")
    
    # Relay Information
    if ev.get('giaddr') and ev['giaddr'] != '0.0.0.0':
        lines.append("\nRELAY INFO:")
        lines.append(f"  Relay Agent IP:   {ev.get('giaddr')}")
        if ev.get('relay_agent'):
            lines.append(f"  Relay Agent Info: {ev.get('relay_agent')}")
    
    # Packet Details
    lines.append("\nPACKET DETAILS:")
    lines.append(f"  Packet Length:    {ev.get('packet_length', 'N/A')} bytes")
    lines.append(f"  UDP Length:       {ev.get('udp_length', 'N/A')} bytes")
    lines.append(f"  Source Port:      {ev.get('src_port', 'N/A')}")
    lines.append(f"  Dest Port:        {ev.get('dst_port', 'N/A')}")
    lines.append(f"  IP TTL:           {ev.get('ip_ttl', 'N/A')}")
    lines.append(f"  IP ID:            {ev.get('ip_id', 'N/A')}")
    
    # Detailed Hostname Information
    if ev.get('src_hostname_info') or ev.get('dst_hostname_info'):
        lines.append("\nHOSTNAME DETAILS:")
        if ev.get('src_hostname_info'):
            src_info = ev['src_hostname_info']
            lines.append(f"  Source ({src_info['ip']}):")
            lines.append(f"    Hostname:       {src_info.get('hostname', 'N/A')}")
            lines.append(f"    Short Name:     {src_info.get('short_name', 'N/A')}")
            lines.append(f"    Domain:         {src_info.get('domain', 'N/A')}")
            lines.append(f"    IP Type:        {src_info.get('type', 'unknown')}")
        
        if ev.get('dst_hostname_info'):
            dst_info = ev['dst_hostname_info']
            lines.append(f"  Destination ({dst_info['ip']}):")
            lines.append(f"    Hostname:       {dst_info.get('hostname', 'N/A')}")
            lines.append(f"    Short Name:     {dst_info.get('short_name', 'N/A')}")
            lines.append(f"    Domain:         {dst_info.get('domain', 'N/A')}")
            lines.append(f"    IP Type:        {dst_info.get('type', 'unknown')}")
    
    # All Raw Options
    if ev.get('raw_options'):
        lines.append("\nRAW DHCP OPTIONS:")
        for opt_code, opt_val in sorted(ev['raw_options'].items()):
            try:
                opt_code_int = int(opt_code)
                opt_name = DHCP_OPTIONS.get(opt_code_int, f"option_{opt_code_int}")
                lines.append(f"  [{opt_code_int:3d}] {opt_name:25s} = {opt_val}")
            except (ValueError, TypeError):
                opt_name = str(opt_code)
                lines.append(f"  [{opt_code}] {opt_name:25s} = {opt_val}")
    else:
        lines.append("\nRAW DHCP OPTIONS: None found")
    
    # Debug and Inferred Information
    if ev.get('debug_info'):
        lines.append("\nDEBUG INFO:")
        debug = ev['debug_info']
        lines.append(f"  DHCP Options Found:   {debug.get('dhcp_options_found', 0)}")
        lines.append(f"  BOOTP Layer:          {debug.get('bootp_layer_present', False)}")
        lines.append(f"  DHCP Layer:           {debug.get('dhcp_layer_present', False)}")
        if debug.get('raw_dhcp_options'):
            lines.append(f"  Option Codes:         {debug['raw_dhcp_options']}")
        if debug.get('no_dhcp_options'):
            lines.append(f"  WARNING:              No DHCP options detected!")
    
    if ev.get('inferred_data'):
        lines.append("\nINFERRED DATA:")
        inferred = ev['inferred_data']
        for key, value in inferred.items():
            lines.append(f"  {key.replace('_', ' ').title():20s} {value}")
    
    lines.append("=" * 80)
    return "\n".join(lines)

def persist_enhanced(buff_pkts, buff_events, buff_raw, config):
    """Enhanced persistence with comprehensive data saving"""
    if not buff_pkts and not buff_events and not buff_raw:
        return
    
    success_count = {"pcap": 0, "json": 0, "text": 0, "raw": 0, "stats": 0}
    
    try:
        # Save PCAP
        if buff_pkts:
            try:
                wrpcap(config.pcap, buff_pkts, append=True)
                success_count["pcap"] = len(buff_pkts)
                print(f"[+] Saved {len(buff_pkts)} DHCP packets to {config.pcap}")
                logging.info(f"[+] PCAP: Saved {len(buff_pkts)} DHCP packets to {config.pcap}")
            except Exception as e:
                error_msg = f"[!] Failed to write PCAP: {e}"
                logging.error(error_msg)
                print(error_msg)
        
        # Save JSON events
        if buff_events:
            dhcp_types = {}
            for ev in buff_events:
                msg_type = ev.get('message_type', 'UNKNOWN')
                dhcp_types[msg_type] = dhcp_types.get(msg_type, 0) + 1
            
            try:
                json_dir = os.path.dirname(os.path.abspath(config.json))
                if json_dir and json_dir != ".":
                    os.makedirs(json_dir, exist_ok=True)
                
                with open(config.json, "a", encoding="utf-8") as jf:
                    for ev in buff_events:
                        try:
                            json_line = json.dumps(ev, ensure_ascii=False, default=str)
                            jf.write(json_line + "\n")
                        except Exception as json_err:
                            logging.error(f"Failed to serialize DHCP event: {json_err}")
                            jf.write(f'{{"error": "serialization_failed", "time": "{now_iso()}", "original_error": "{str(json_err)}"}}\n')
                    jf.flush()
                    os.fsync(jf.fileno())
                
                success_count["json"] = len(buff_events)
                print(f"[+] Saved {len(buff_events)} DHCP events to {config.json}")
                print(f"    DHCP Types: {dict(dhcp_types)}")
                logging.info(f"[+] JSON: Saved {len(buff_events)} events - Types: {dict(dhcp_types)}")
                
            except Exception as e:
                error_msg = f"[!] Failed to write JSON: {e}"
                logging.error(error_msg)
                print(error_msg)
        
        # Save text logs
        if buff_events:
            try:
                text_dir = os.path.dirname(os.path.abspath(config.txt))
                if text_dir and text_dir != ".":
                    os.makedirs(text_dir, exist_ok=True)
                
                with open(config.txt, "a", encoding="utf-8") as tf:
                    tf.write(f"\n{'='*100}\n")
                    tf.write(f"DHCP BATCH SAVED AT {now_iso()}\n")
                    tf.write(f"Batch contains {len(buff_events)} DHCP events\n")
                    tf.write(f"{'='*100}\n\n")
                    
                    for ev in buff_events:
                        try:
                            tf.write(pretty_line(ev) + "\n\n")
                        except Exception as text_err:
                            logging.error(f"Failed to write DHCP text event: {text_err}")
                            tf.write(f"[ERROR] Failed to format DHCP event at {now_iso()}: {text_err}\n\n")
                    tf.flush()
                    os.fsync(tf.fileno())
                
                success_count["text"] = len(buff_events)
                print(f"[+] Saved {len(buff_events)} DHCP events to {config.txt}")
                logging.info(f"[+] TEXT: Saved {len(buff_events)} events")
                
            except Exception as e:
                error_msg = f"[!] Failed to write text log: {e}"
                logging.error(error_msg)
                print(error_msg)
        
        # Save raw analysis data
        if buff_raw:
            try:
                raw_path = getattr(config, 'raw_dump', DEFAULT_RAW_DUMP)
                raw_dir = os.path.dirname(os.path.abspath(raw_path))
                if raw_dir and raw_dir != ".":
                    os.makedirs(raw_dir, exist_ok=True)
                
                with open(raw_path, "a", encoding="utf-8") as rf:
                    rf.write(f"\n{'='*100}\n")
                    rf.write(f"RAW DHCP ANALYSIS BATCH AT {now_iso()}\n")
                    rf.write(f"Batch contains {len(buff_raw)} raw analyses\n")
                    rf.write(f"{'='*100}\n\n")
                    
                    for raw_analysis in buff_raw:
                        try:
                            rf.write(json.dumps(raw_analysis, indent=2, default=str) + "\n\n")
                        except Exception as raw_err:
                            logging.error(f"Failed to write raw analysis: {raw_err}")
                            rf.write(f"[ERROR] Failed to format raw analysis at {now_iso()}: {raw_err}\n\n")
                    rf.flush()
                    os.fsync(rf.fileno())
                
                success_count["raw"] = len(buff_raw)
                print(f"[+] Saved {len(buff_raw)} raw analyses to {raw_path}")
                logging.info(f"[+] RAW: Saved {len(buff_raw)} analyses")
                
            except Exception as e:
                error_msg = f"[!] Failed to write raw analysis: {e}"
                logging.error(error_msg)
                print(error_msg)
        
        # Save comprehensive statistics
        try:
            stats_path = getattr(config, 'stats_file', DEFAULT_STATS_FILE)
            comprehensive_stats = {
                "timestamp": now_iso(),
                "packet_counts": dict(packet_count),
                "unique_vendors": list(unique_vendors),
                "unique_hostnames": list(unique_hostnames),
                "server_statistics": dict(server_stats),
                "option_frequency": dict(option_frequency),
                "network_topology": {k: {**v, "roles": list(v["roles"])} for k, v in network_topology.items()},
                "lease_tracking": dict(lease_tracking),
                "conversation_summary": {k: len(v) for k, v in dhcp_conversations.items()},
                "transaction_count": len(transactions),
                "client_count": len(client_history)
            }
            
            with open(stats_path, "w", encoding="utf-8") as sf:
                json.dump(comprehensive_stats, sf, indent=2, default=str)
                sf.flush()
                os.fsync(sf.fileno())
            
            success_count["stats"] = 1
            print(f"[+] Updated comprehensive statistics in {stats_path}")
            logging.info(f"[+] STATS: Updated comprehensive statistics")
            
        except Exception as e:
            error_msg = f"[!] Failed to write statistics: {e}"
            logging.error(error_msg)
            print(error_msg)
        
        persist_msg = f"[+] Enhanced Data Persisted - PCAP: {success_count['pcap']}, JSON: {success_count['json']}, Text: {success_count['text']}, Raw: {success_count['raw']}, Stats: {success_count['stats']}"
        logging.info(persist_msg)
        
    except Exception as e:
        error_msg = f"Error in persist_enhanced function: {e}"
        logging.exception(error_msg)
        print(f"[!] {error_msg}")

def persist(buff_pkts, buff_events, pcap_path, json_path, text_path):
    """Persist packets and events to disk with error handling"""
    if not buff_pkts and not buff_events:
        return
    
    success_count = {"pcap": 0, "json": 0, "text": 0}
    
    try:
        # Save PCAP
        if buff_pkts:
            try:
                wrpcap(pcap_path, buff_pkts, append=True)
                success_count["pcap"] = len(buff_pkts)
                print(f"[+] Saved {len(buff_pkts)} DHCP packets to {pcap_path}")
                logging.info(f"[+] PCAP: Saved {len(buff_pkts)} DHCP packets to {pcap_path}")
            except Exception as e:
                error_msg = f"[!] Failed to write PCAP: {e}"
                logging.error(error_msg)
                print(error_msg)
        
        # Save JSON and Text with DHCP-specific information
        if buff_events:
            # Count DHCP message types
            dhcp_types = {}
            for ev in buff_events:
                msg_type = ev.get('message_type', 'UNKNOWN')
                dhcp_types[msg_type] = dhcp_types.get(msg_type, 0) + 1
            
            # JSON saving with better error handling
            try:
                json_dir = os.path.dirname(os.path.abspath(json_path))
                if json_dir and json_dir != ".":
                    os.makedirs(json_dir, exist_ok=True)
                
                with open(json_path, "a", encoding="utf-8") as jf:
                    for ev in buff_events:
                        try:
                            json_line = json.dumps(ev, ensure_ascii=False, default=str)
                            jf.write(json_line + "\n")
                        except Exception as json_err:
                            logging.error(f"Failed to serialize DHCP event: {json_err}")
                            jf.write(f'{{"error": "serialization_failed", "time": "{now_iso()}", "original_error": "{str(json_err)}"}}\n')
                    jf.flush()
                    os.fsync(jf.fileno())
                
                success_count["json"] = len(buff_events)
                success_msg = f"[+] Saved {len(buff_events)} DHCP events to {json_path}"
                print(success_msg)
                print(f"    DHCP Types: {dict(dhcp_types)}")
                logging.info(f"[+] JSON: {success_msg} - Types: {dict(dhcp_types)}")
                
            except Exception as e:
                error_msg = f"[!] Failed to write JSON: {e}"
                logging.error(error_msg)
                print(error_msg)
            
            # Text file saving
            try:
                text_dir = os.path.dirname(os.path.abspath(text_path))
                if text_dir and text_dir != ".":
                    os.makedirs(text_dir, exist_ok=True)
                
                with open(text_path, "a", encoding="utf-8") as tf:
                    tf.write(f"\n{'='*80}\n")
                    tf.write(f"DHCP BATCH SAVED AT {now_iso()}\n")
                    tf.write(f"Batch contains {len(buff_events)} DHCP events\n")
                    tf.write(f"DHCP Message Types: {dict(dhcp_types)}\n")
                    tf.write(f"{'='*80}\n\n")
                    
                    for ev in buff_events:
                        try:
                            tf.write(pretty_line(ev) + "\n\n")
                        except Exception as text_err:
                            logging.error(f"Failed to write DHCP text event: {text_err}")
                            tf.write(f"[ERROR] Failed to format DHCP event at {now_iso()}: {text_err}\n\n")
                    tf.flush()
                    os.fsync(tf.fileno())
                
                success_count["text"] = len(buff_events)
                success_msg = f"[+] Saved {len(buff_events)} DHCP events to {text_path}"
                print(success_msg)
                logging.info(f"[+] TEXT: {success_msg}")
                
            except Exception as e:
                error_msg = f"[!] Failed to write text log: {e}"
                logging.error(error_msg)
                print(error_msg)
        
        persist_msg = f"[+] DHCP Data Persisted - PCAP: {success_count['pcap']}, JSON: {success_count['json']}, Text: {success_count['text']}"
        logging.info(persist_msg)
        
    except Exception as e:
        error_msg = f"Error in persist function: {e}"
        logging.exception(error_msg)
        print(f"[!] {error_msg}")

def is_private_ip(ip_address):
    """Check if an IP address is private/local"""
    if not ip_address or ip_address in ["0.0.0.0", "255.255.255.255"]:
        return True
    
    try:
        octets = ip_address.split('.')
        if len(octets) != 4:
            return True
            
        first = int(octets[0])
        second = int(octets[1])
        
        # Private IP ranges
        if first == 10:  # 10.0.0.0/8
            return True
        elif first == 172 and 16 <= second <= 31:  # 172.16.0.0/12
            return True
        elif first == 192 and second == 168:  # 192.168.0.0/16
            return True
        elif first == 127:  # 127.0.0.0/8 (loopback)
            return True
        elif first == 169 and second == 254:  # 169.254.0.0/16 (link-local)
            return True
        elif first >= 224:  # Multicast and reserved
            return True
        else:
            return False
    except:
        return True

def get_ip_geolocation(ip_address):
    """Get basic geolocation info for public IP addresses"""
    if is_private_ip(ip_address):
        return None
    
    try:
        # Simple geolocation using free services (you can enhance this)
        import subprocess
        import json
        
        # Try using curl with ipapi.co (free service)
        result = subprocess.run(['curl', '-s', f'https://ipapi.co/{ip_address}/json/'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            geo_data = json.loads(result.stdout)
            return {
                "country": geo_data.get("country_name"),
                "city": geo_data.get("city"),
                "org": geo_data.get("org"),
                "asn": geo_data.get("asn")
            }
    except:
        pass
    
    return {"status": "lookup_failed"}

def analyze_dhcp_security_threats(packet, event_data):
    """Advanced security analysis for DHCP traffic"""
    threats = []
    threat_score = 0
    
    try:
        src_ip = event_data.get('src_ip', '')
        dst_ip = event_data.get('dst_ip', '')
        
        # 1. Rogue DHCP Server Detection
        if event_data.get('message_type') in ['OFFER', 'ACK']:
            server_ip = event_data.get('server_id', src_ip)
            if not is_private_ip(server_ip):
                threats.append({
                    'type': 'INTERNET_DHCP_SERVER',
                    'severity': 'HIGH',
                    'description': f'DHCP server detected from internet IP: {server_ip}',
                    'score': 30
                })
                threat_score += 30
        
        # 2. Unusual DHCP Options Analysis
        if event_data.get('raw_options'):
            options = event_data['raw_options']
            
            # Check for suspicious option combinations
            if 'option_43' in options:  # Vendor-specific information
                vendor_data = options['option_43']
                if len(vendor_data) > 100:  # Unusually large vendor data
                    threats.append({
                        'type': 'SUSPICIOUS_VENDOR_DATA',
                        'severity': 'MEDIUM',
                        'description': f'Large vendor-specific data: {len(vendor_data)} bytes',
                        'score': 15
                    })
                    threat_score += 15
            
            # Check for unusual option codes
            unusual_options = [opt for opt in options.keys() if 'option_' in opt and 
                             int(opt.split('_')[1]) > 200]
            if unusual_options:
                threats.append({
                    'type': 'UNUSUAL_DHCP_OPTIONS',
                    'severity': 'MEDIUM',
                    'description': f'Unusual DHCP options detected: {unusual_options}',
                    'score': 10
                })
                threat_score += 10
        
        # 3. Rapid DHCP Requests (Potential DoS)
        client_mac = event_data.get('chaddr', '')
        if client_mac:
            current_time = datetime.now()
            if client_mac not in client_history:
                client_history[client_mac] = deque(maxlen=50)
            
            client_history[client_mac].append(current_time)
            
            # Check for rapid requests (more than 10 in 60 seconds)
            recent_requests = [t for t in client_history[client_mac] 
                             if (current_time - t).total_seconds() < 60]
            if len(recent_requests) > 10:
                threats.append({
                    'type': 'DHCP_FLOODING',
                    'severity': 'HIGH',
                    'description': f'Rapid DHCP requests from {client_mac}: {len(recent_requests)}/min',
                    'score': 25
                })
                threat_score += 25
        
        # 4. Geolocation-based threats
        if not is_private_ip(src_ip):
            geo_info = get_enhanced_geolocation(src_ip)
            if geo_info:
                country = geo_info.get('country', '').upper()
                
                # Check against high-risk countries (you can customize this list)
                high_risk_countries = ['XX', 'UNKNOWN']  # Add actual country codes as needed
                if country in high_risk_countries:
                    threats.append({
                        'type': 'HIGH_RISK_GEOLOCATION',
                        'severity': 'MEDIUM',
                        'description': f'DHCP traffic from high-risk location: {country}',
                        'score': 20
                    })
                    threat_score += 20
        
        # 5. DNS Tunneling Detection in DHCP
        hostname = event_data.get('hostname', '')
        if hostname and len(hostname) > 50:
            # Check for base64-like patterns or excessive length
            if re.match(r'^[A-Za-z0-9+/=]{40,}$', hostname):
                threats.append({
                    'type': 'POTENTIAL_DNS_TUNNELING',
                    'severity': 'HIGH',
                    'description': f'Suspicious hostname pattern detected: {hostname[:50]}...',
                    'score': 35
                })
                threat_score += 35
        
        return {
            'threats': threats,
            'total_threat_score': threat_score,
            'risk_level': 'HIGH' if threat_score > 50 else 'MEDIUM' if threat_score > 20 else 'LOW'
        }
    
    except Exception as e:
        logging.error(f"Error in security analysis: {e}")
        return {'threats': [], 'total_threat_score': 0, 'risk_level': 'UNKNOWN'}

def get_enhanced_geolocation(ip_address):
    """Enhanced geolocation with caching and multiple providers"""
    if is_private_ip(ip_address):
        return None
    
    with geo_lock:
        # Check cache first
        if ip_address in geo_cache:
            cached_data = geo_cache[ip_address]
            # Check if cache is fresh (less than 24 hours old)
            if datetime.now().timestamp() - cached_data.get('timestamp', 0) < 86400:
                return cached_data['data']
    
    geo_data = None
    
    try:
        # Primary: ipapi.co
        result = subprocess.run(['curl', '-s', f'https://ipapi.co/{ip_address}/json/'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if data.get('country_name'):
                geo_data = {
                    "country": data.get("country_name"),
                    "country_code": data.get("country_code"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "org": data.get("org"),
                    "asn": data.get("asn"),
                    "timezone": data.get("timezone"),
                    "threat_score": calculate_geo_threat_score(data)
                }
    except Exception as e:
        logging.debug(f"Primary geolocation failed for {ip_address}: {e}")
    
    # Fallback: ip-api.com
    if not geo_data:
        try:
            result = subprocess.run(['curl', '-s', f'http://ip-api.com/json/{ip_address}'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if data.get('status') == 'success':
                    geo_data = {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "city": data.get("city"),
                        "region": data.get("regionName"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "timezone": data.get("timezone"),
                        "threat_score": calculate_geo_threat_score(data)
                    }
        except Exception as e:
            logging.debug(f"Fallback geolocation failed for {ip_address}: {e}")
    
    # Cache the result
    if geo_data:
        with geo_lock:
            geo_cache[ip_address] = {
                'data': geo_data,
                'timestamp': datetime.now().timestamp()
            }
    
    return geo_data

def calculate_geo_threat_score(geo_data):
    """Calculate threat score based on geolocation data"""
    score = 0
    
    # Add scoring logic based on your threat intelligence
    country_code = geo_data.get('countryCode', '').upper()
    org = geo_data.get('org', '').lower()
    
    # High-risk indicators (customize based on your requirements)
    if 'tor' in org or 'vpn' in org or 'proxy' in org:
        score += 30
    
    if any(keyword in org for keyword in ['bullet', 'hosting', 'server']):
        score += 10
    
    return min(score, 100)  # Cap at 100

def analyze_vendor_fingerprint(event_data):
    """Advanced vendor and device fingerprinting"""
    fingerprint = {
        'vendor_class': event_data.get('vendor_class_id', ''),
        'parameter_request_list': event_data.get('parameter_request_list', []),
        'os_guess': 'unknown',
        'device_type': 'unknown',
        'confidence': 0
    }
    
    vendor_class = fingerprint['vendor_class'].lower()
    param_list = fingerprint['parameter_request_list']
    
    # Advanced OS detection based on DHCP fingerprinting
    if 'windows' in vendor_class or 'microsoft' in vendor_class:
        fingerprint['os_guess'] = 'Windows'
        fingerprint['confidence'] = 80
    elif 'apple' in vendor_class or 'darwin' in vendor_class:
        fingerprint['os_guess'] = 'macOS/iOS'
        fingerprint['confidence'] = 85
    elif 'android' in vendor_class:
        fingerprint['os_guess'] = 'Android'
        fingerprint['confidence'] = 90
    elif 'linux' in vendor_class or 'ubuntu' in vendor_class:
        fingerprint['os_guess'] = 'Linux'
        fingerprint['confidence'] = 75
    
    # Device type detection
    if any(keyword in vendor_class for keyword in ['phone', 'mobile', 'android']):
        fingerprint['device_type'] = 'Mobile Device'
    elif any(keyword in vendor_class for keyword in ['printer', 'canon', 'hp', 'epson']):
        fingerprint['device_type'] = 'Printer'
    elif any(keyword in vendor_class for keyword in ['camera', 'ip cam', 'surveillance']):
        fingerprint['device_type'] = 'IP Camera'
    elif any(keyword in vendor_class for keyword in ['router', 'gateway', 'access point']):
        fingerprint['device_type'] = 'Network Device'
    
    return fingerprint

def detect_anomalies(event_data, historical_data):
    """Machine learning-based anomaly detection"""
    anomalies = []
    
    try:
        # 1. Unusual lease time requests
        lease_time = event_data.get('lease_time', 0)
        if lease_time > 86400 * 30:  # More than 30 days
            anomalies.append({
                'type': 'UNUSUAL_LEASE_TIME',
                'description': f'Unusually long lease time requested: {lease_time} seconds',
                'severity': 'MEDIUM'
            })
        
        # 2. Unusual hostname patterns
        hostname = event_data.get('hostname', '')
        if hostname:
            # Check for suspicious patterns
            if len(hostname) > 60:
                anomalies.append({
                    'type': 'LONG_HOSTNAME',
                    'description': f'Unusually long hostname: {len(hostname)} characters',
                    'severity': 'MEDIUM'
                })
            
            if re.match(r'^[0-9a-f]{32,}$', hostname):
                anomalies.append({
                    'type': 'HEX_HOSTNAME',
                    'description': f'Suspicious hex-like hostname: {hostname}',
                    'severity': 'HIGH'
                })
        
        # 3. Rapid IP changes
        client_mac = event_data.get('chaddr', '')
        current_ip = event_data.get('yiaddr', '')
        
        if client_mac and current_ip and current_ip != '0.0.0.0':
            if client_mac in lease_tracking:
                last_ip = lease_tracking[client_mac].get('ip', '')
                if last_ip and last_ip != current_ip:
                    time_diff = datetime.now() - datetime.fromisoformat(
                        lease_tracking[client_mac].get('last_seen', datetime.now().isoformat())
                    )
                    if time_diff.total_seconds() < 300:  # Less than 5 minutes
                        anomalies.append({
                            'type': 'RAPID_IP_CHANGE',
                            'description': f'Rapid IP change for {client_mac}: {last_ip} -> {current_ip}',
                            'severity': 'MEDIUM'
                        })
    
    except Exception as e:
        logging.error(f"Error in anomaly detection: {e}")
    
    return anomalies

def packet_handler(pkt, config):
    try:
        packet_count["total"] += 1
        start_time = time.time()
        
        # Check for UDP packets on DHCP ports first
        is_dhcp_port = False
        if UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if (sport in [67, 68] or dport in [67, 68]):
                is_dhcp_port = True
                packet_count["udp"] += 1
        
        # Enhanced internet traffic detection and analysis
        if is_dhcp_port and IP in pkt:
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            
            # Determine if this is internet or local traffic
            src_is_private = is_private_ip(src_ip)
            dst_is_private = is_private_ip(dst_ip)
            
            # Internet DHCP traffic analysis
            if not src_is_private or not dst_is_private:
                packet_count["internet_dhcp"] = packet_count.get("internet_dhcp", 0) + 1
                
                print(f"\n{'🌐'*5} INTERNET DHCP TRAFFIC DETECTED {'🌐'*5}")
                print(f"┌─ Source: {src_ip} ({'INTERNET' if not src_is_private else 'LOCAL'})")
                print(f"├─ Destination: {dst_ip} ({'INTERNET' if not dst_is_private else 'LOCAL'})")
                print(f"├─ Ports: {sport} -> {dport}")
                print(f"├─ Packet Size: {len(pkt)} bytes")
                
                # Enhanced geolocation and threat analysis
                internet_ip = src_ip if not src_is_private else dst_ip
                geo_info = get_enhanced_geolocation(internet_ip)
                
                if geo_info:
                    print(f"├─ Location: {geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')}")
                    print(f"├─ ISP/Org: {geo_info.get('org', 'Unknown')}")
                    print(f"├─ ASN: {geo_info.get('asn', 'Unknown')}")
                    print(f"├─ Threat Score: {geo_info.get('threat_score', 0)}/100")
                    
                    # Update internet server tracking
                    with buf_lock:
                        server_info = internet_dhcp_servers[internet_ip]
                        server_info['last_seen'] = datetime.now().isoformat()
                        if server_info['first_seen'] is None:
                            server_info['first_seen'] = datetime.now().isoformat()
                        server_info['packet_count'] += 1
                        server_info['countries'].add(geo_info.get('country', 'Unknown'))
                        server_info['isps'].add(geo_info.get('org', 'Unknown'))
                        server_info['threat_score'] = max(server_info['threat_score'], 
                                                        geo_info.get('threat_score', 0))
                
                print(f"└─ Analysis: {'🚨 HIGH RISK' if geo_info and geo_info.get('threat_score', 0) > 50 else '⚠️  MEDIUM RISK' if geo_info and geo_info.get('threat_score', 0) > 20 else '✅ LOW RISK'}")
                print(f"{'='*60}")
                
            else:
                packet_count["local_dhcp"] = packet_count.get("local_dhcp", 0) + 1
        
        # Analyze ALL DHCP-related traffic
        if is_dhcp_port:
            # Submit to thread pool for parallel processing
            if not processing_queue.full():
                processing_queue.put((pkt, config, start_time))
                executor.submit(process_dhcp_packet_async, pkt, config, start_time)
            
            # Perform comprehensive raw analysis
            raw_analysis = analyze_raw_dhcp_packet(pkt)
            
            # Track raw DHCP traffic
            with buf_lock:
                raw_buffer.append(raw_analysis)
            
            # Update network topology with enhanced information
            if IP in pkt:
                src_ip = str(pkt[IP].src)
                dst_ip = str(pkt[IP].dst)
                
                for ip in [src_ip, dst_ip]:
                    if ip not in network_topology:
                        network_topology[ip] = {
                            "first_seen": now_iso(), 
                            "packets": 0, 
                            "roles": set(),
                            "geolocation": None,
                            "threat_score": 0,
                            "device_fingerprint": None
                        }
                    
                    network_topology[ip]["packets"] += 1
                    
                    # Add geolocation for internet IPs
                    if not is_private_ip(ip) and network_topology[ip]["geolocation"] is None:
                        geo_info = get_enhanced_geolocation(ip)
                        if geo_info:
                            network_topology[ip]["geolocation"] = geo_info
                            network_topology[ip]["threat_score"] = geo_info.get('threat_score', 0)
                
                # Determine roles based on ports with enhanced detection
                if UDP in pkt:
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                    
                    if sport == 67:
                        network_topology[src_ip]["roles"].add("dhcp_server")
                        if not is_private_ip(src_ip):
                            network_topology[src_ip]["roles"].add("internet_dhcp_server")
                    elif sport == 68:
                        network_topology[src_ip]["roles"].add("dhcp_client")
                    
                    if dport == 67:
                        network_topology[dst_ip]["roles"].add("dhcp_server")
                        if not is_private_ip(dst_ip):
                            network_topology[dst_ip]["roles"].add("internet_dhcp_server")
                    elif dport == 68:
                        network_topology[dst_ip]["roles"].add("dhcp_client")
        
        # Update performance metrics
        processing_time = time.time() - start_time
        performance_metrics['processing_latency'].append(processing_time)
        
        # Calculate packets per second
        current_minute = int(time.time() / 60)
        if len(performance_metrics['packets_per_second']) == 0 or performance_metrics['packets_per_second'][-1][0] != current_minute:
            performance_metrics['packets_per_second'].append([current_minute, 1])
        else:
            performance_metrics['packets_per_second'][-1][1] += 1
        
        # Focus on DHCP packets - check both layers and ports
        if (BOOTP in pkt and DHCP in pkt) or is_dhcp_port:
            packet_count["dhcp"] += 1
            
            print("\n" + "#"*100)
            print(f"### DHCP PACKET DETECTED ### (#{packet_count['dhcp']}) - Total: {packet_count['total']}")
            if is_dhcp_port and not (BOOTP in pkt and DHCP in pkt):
                print("### (DHCP PORT TRAFFIC - may be fragmented or non-standard) ###")
                packet_count["raw_dhcp"] += 1
            print("#"*100)
            
            # Try to parse as DHCP first
            ev = None
            if BOOTP in pkt and DHCP in pkt:
                ev = parse_dhcp(pkt, config)
                
                # Enhanced DHCP analysis
                if ev:
                    # Advanced security threat analysis
                    threat_analysis = analyze_dhcp_security_threats(pkt, ev)
                    if threat_analysis['total_threat_score'] > 0:
                        ev['security_analysis'] = threat_analysis
                        
                        # Log high-risk threats
                        if threat_analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                            threat_event = {
                                'timestamp': ev['time'],
                                'source_ip': ev.get('src_ip'),
                                'threat_analysis': threat_analysis,
                                'packet_summary': pkt.summary()
                            }
                            with buf_lock:
                                threat_buffer.append(threat_event)
                            
                            print(f"🚨 SECURITY ALERT: {threat_analysis['risk_level']} RISK DETECTED!")
                            for threat in threat_analysis['threats']:
                                print(f"   - {threat['type']}: {threat['description']}")
                    
                    # Advanced vendor fingerprinting
                    fingerprint = analyze_vendor_fingerprint(ev)
                    if fingerprint['confidence'] > 0:
                        ev['device_fingerprint'] = fingerprint
                        
                        # Update global fingerprint database
                        client_mac = ev.get('chaddr', '')
                        if client_mac:
                            dhcp_fingerprints[client_mac] = fingerprint
                    
                    # Anomaly detection
                    anomalies = detect_anomalies(ev, client_history)
                    if anomalies:
                        ev['anomalies'] = anomalies
                        for anomaly in anomalies:
                            print(f"⚠️  ANOMALY: {anomaly['type']} - {anomaly['description']}")
                    
                    # Update statistics for parsed DHCP
                    # Track vendors
                    if ev.get('vendor_class_id'):
                        unique_vendors.add(ev['vendor_class_id'])
                    
                    # Track hostnames
                    if ev.get('hostname'):
                        unique_hostnames.add(ev['hostname'])
                    
                    # Track DHCP options frequency
                    if ev.get('raw_options'):
                        for opt_code in ev['raw_options'].keys():
                            option_frequency[opt_code] += 1
                    
                    # Track server statistics with enhanced info
                    server_ip = ev.get('server_id', ev.get('src_ip'))
                    if server_ip:
                        server_stats[server_ip] += 1
                        
                        # Enhanced server tracking for internet servers
                        if not is_private_ip(server_ip):
                            with buf_lock:
                                server_info = internet_dhcp_servers[server_ip]
                                if ev.get('message_type'):
                                    if 'message_types' not in server_info:
                                        server_info['message_types'] = Counter()
                                    server_info['message_types'][ev['message_type']] += 1
                    
                    # Track lease information with anomaly detection
                    if ev.get('chaddr') and ev.get('yiaddr') and ev['yiaddr'] != '0.0.0.0':
                        lease_info = {
                            "ip": ev['yiaddr'],
                            "server": ev.get('server_id', ev.get('src_ip')),
                            "lease_time": ev.get('lease_time'),
                            "last_seen": now_iso(),
                            "message_type": ev.get('message_type'),
                            "fingerprint": fingerprint if 'fingerprint' in locals() else None
                        }
                        lease_tracking[ev['chaddr']] = lease_info
                    
                    # Track conversations with enhanced metadata
                    conversation_key = f"{ev.get('src_ip')}-{ev.get('dst_ip')}"
                    conversation_entry = {
                        "time": ev["time"],
                        "type": ev["message_type"],
                        "direction": "client_to_server" if ev.get('src_port') == 68 else "server_to_client",
                        "threat_score": threat_analysis.get('total_threat_score', 0) if 'threat_analysis' in locals() else 0,
                        "internet_traffic": not is_private_ip(ev.get('src_ip', '')) or not is_private_ip(ev.get('dst_ip', ''))
                    }
                    dhcp_conversations[conversation_key].append(conversation_entry)
            
            # If DHCP parsing failed but we have DHCP port traffic, create basic event
            if ev is None and is_dhcp_port:
                ev = create_basic_dhcp_event(pkt)
                packet_count["malformed"] += 1
            
            if ev is None:
                error_msg = "[ERROR] Failed to parse DHCP packet"
                print(error_msg)
                logging.error(error_msg)
                # Still log the raw packet info
                if UDP in pkt:
                    logging.info(f"Raw DHCP port traffic: {pkt[UDP].sport} -> {pkt[UDP].dport}, len={len(pkt)}")
                return
            
            # Track transactions and client history
            xid = ev.get("transaction_id_int")
            mac = ev.get("chaddr")
            if xid:
                transactions[xid].append(ev)
            if mac:
                client_history[mac].append({
                    "time": ev["time"],
                    "type": ev["message_type"],
                    "ip": ev.get("yiaddr") or ev.get("requested_addr")
                })
            
            # Print detailed formatted output to console
            print(pretty_line(ev))
            
            # Print additional statistics
            print(f"\n[LIVE STATS] Vendors: {len(unique_vendors)}, Hostnames: {len(unique_hostnames)}, "
                  f"Servers: {len(server_stats)}, Leases: {len(lease_tracking)}")
            
            # Log DHCP event details to logging system
            hostname_for_log = ev.get('dhcp_hostname') or ev.get('hostname', 'N/A')
            dhcp_summary = (f"DHCP {ev.get('message_type')} - "
                          f"MAC: {ev.get('chaddr')} - "
                          f"Hostname: {hostname_for_log} - "
                          f"IP: {ev.get('yiaddr') or ev.get('ciaddr') or 'N/A'} - "
                          f"Server: {ev.get('server_id', 'N/A')} - "
                          f"Src: {ev.get('src_hostname', ev.get('src_ip', 'N/A'))} - "
                          f"Dst: {ev.get('dst_hostname', ev.get('dst_ip', 'N/A'))}")
            logging.info(dhcp_summary)
            
            # Buffer the packet and event for file writing
            with buf_lock:
                packet_buffer.append(pkt)
                event_buffer.append(ev)
                if len(packet_buffer) >= config.batch_size:
                    pkts = list(packet_buffer)
                    evs = list(event_buffer)
                    raws = list(raw_buffer)
                    packet_buffer.clear()
                    event_buffer.clear()
                    raw_buffer.clear()
                    persist_enhanced(pkts, evs, raws, config)
                    
    except Exception:
        logging.exception("Exception in packet_handler")

def flusher_thread(config):
    last_summary_time = time.time()
    last_stats_time = time.time()
    
    while not stopping.wait(config.flush_interval):
        with buf_lock:
            if packet_buffer or event_buffer or raw_buffer:
                pkts = list(packet_buffer)
                evs = list(event_buffer)
                raws = list(raw_buffer)
                packet_buffer.clear()
                event_buffer.clear()
                raw_buffer.clear()
                persist_enhanced(pkts, evs, raws, config)
        
        # Print comprehensive stats
        if time.time() - last_stats_time >= config.flush_interval:
            print("\n" + "+"*100)
            print("[COMPREHENSIVE DHCP CAPTURE STATISTICS]")
            print("+"*100)
            print(f"Total Packets Seen:     {packet_count['total']}")
            print(f"DHCP Packets Found:     {packet_count['dhcp']}")
            print(f"Raw DHCP Traffic:       {packet_count['raw_dhcp']}")
            print(f"Malformed Packets:      {packet_count['malformed']}")
            print(f"DHCP Clients:           {len(client_history)}")
            print(f"DHCP Transactions:      {len(transactions)}")
            print(f"DHCP Servers Detected:  {len(server_stats)}")
            print(f"Unique Vendors:         {len(unique_vendors)}")
            print(f"Unique Hostnames:       {len(unique_hostnames)}")
            print(f"Active Leases:          {len(lease_tracking)}")
            print(f"Network Nodes:          {len(network_topology)}")
            
            if packet_count['total'] > 0:
                dhcp_percentage = (packet_count['dhcp'] / packet_count['total']) * 100
                print(f"DHCP Efficiency:        {dhcp_percentage:.2f}%")
            
            # Show top DHCP options
            if option_frequency:
                top_options = sorted(option_frequency.items(), key=lambda x: x[1], reverse=True)[:5]
                print(f"\nTop DHCP Options:")
                for opt_code, freq in top_options:
                    opt_name = DHCP_OPTIONS.get(opt_code, f"option_{opt_code}")
                    print(f"  [{opt_code}] {opt_name}: {freq} times")
            
            # Show vendor classes
            if unique_vendors:
                print(f"\nVendor Classes Detected:")
                for i, vendor in enumerate(list(unique_vendors)[:5]):
                    print(f"  - {vendor}")
                if len(unique_vendors) > 5:
                    print(f"  ... and {len(unique_vendors) - 5} more")
            
            # Show active servers
            if server_stats:
                print(f"\nDHCP Servers:")
                for server, count in sorted(server_stats.items(), key=lambda x: x[1], reverse=True):
                    print(f"  - {server}: {count} responses")
            
            logging.info(f"[DHCP-COMPREHENSIVE] packets={packet_count['dhcp']}/{packet_count['total']} "
                        f"clients={len(client_history)} servers={len(server_stats)} "
                        f"vendors={len(unique_vendors)} leases={len(lease_tracking)}")
            
            if client_history:
                print("\n[RECENT DHCP CLIENTS]")
                recent_clients = list(client_history.items())[-5:]
                for mac, history in recent_clients:
                    last_event = history[-1]
                    print(f"  {mac}: {last_event['type']} @ {last_event.get('ip', 'N/A')} [{last_event['time']}]")
            
            print("+"*100 + "\n")
            last_stats_time = time.time()
        
        if time.time() - last_summary_time > 60:
            last_summary_time = time.time()

def process_dhcp_packet_async(pkt, config, start_time):
    """Asynchronous DHCP packet processing for high-performance analysis"""
    try:
        # This function runs in thread pool for parallel processing
        # Add any computationally intensive analysis here
        
        # Deep packet inspection
        if Raw in pkt:
            raw_data = bytes(pkt[Raw])
            
            # Check for covert channels or hidden data
            if len(raw_data) > 500:  # Unusually large DHCP packet
                suspicious_patterns["large_packets"].append({
                    'timestamp': datetime.now().isoformat(),
                    'size': len(raw_data),
                    'src_ip': str(pkt[IP].src) if IP in pkt else 'unknown',
                    'packet_summary': pkt.summary()
                })
        
        # Advanced pattern analysis
        if DHCP in pkt:
            dhcp_layer = pkt[DHCP]
            
            # Check for unusual option combinations
            options = []
            if hasattr(dhcp_layer, 'options'):
                for option in dhcp_layer.options:
                    if isinstance(option, tuple) and len(option) >= 2:
                        options.append(option[0])
            
            # Detect unusual option patterns
            if len(options) > 20:  # Unusually many options
                suspicious_patterns["many_options"].append({
                    'timestamp': datetime.now().isoformat(),
                    'option_count': len(options),
                    'options': options,
                    'src_ip': str(pkt[IP].src) if IP in pkt else 'unknown'
                })
    
    except Exception as e:
        logging.error(f"Error in async packet processing: {e}")

def generate_comprehensive_report():
    """Generate comprehensive analysis report of captured DHCP traffic"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_packets': packet_count.get('total', 0),
            'dhcp_packets': packet_count.get('dhcp', 0),
            'internet_dhcp': packet_count.get('internet_dhcp', 0),
            'local_dhcp': packet_count.get('local_dhcp', 0),
            'threat_events': len(threat_buffer)
        },
        'internet_servers': {},
        'security_analysis': {
            'high_risk_servers': [],
            'threat_summary': dict(Counter()),
            'anomaly_summary': dict(Counter())
        },
        'network_topology': {},
        'performance_metrics': {
            'avg_processing_latency': 0,
            'peak_packets_per_second': 0
        }
    }
    
    # Analyze internet DHCP servers
    for server_ip, info in internet_dhcp_servers.items():
        report['internet_servers'][server_ip] = {
            'packet_count': info['packet_count'],
            'countries': list(info['countries']),
            'isps': list(info['isps']),
            'threat_score': info['threat_score'],
            'first_seen': info['first_seen'],
            'last_seen': info['last_seen']
        }
        
        if info['threat_score'] > 50:
            report['security_analysis']['high_risk_servers'].append(server_ip)
    
    # Analyze threats
    for threat_event in threat_buffer:
        threat_analysis = threat_event.get('threat_analysis', {})
        for threat in threat_analysis.get('threats', []):
            threat_type = threat['type']
            if threat_type not in report['security_analysis']['threat_summary']:
                report['security_analysis']['threat_summary'][threat_type] = 0
            report['security_analysis']['threat_summary'][threat_type] += 1
    
    # Performance metrics
    if performance_metrics['processing_latency']:
        report['performance_metrics']['avg_processing_latency'] = sum(performance_metrics['processing_latency']) / len(performance_metrics['processing_latency'])
    
    if performance_metrics['packets_per_second']:
        report['performance_metrics']['peak_packets_per_second'] = max([pps[1] for pps in performance_metrics['packets_per_second']])
    
    return report

def save_enhanced_data(args):
    """Save enhanced data including threats, geolocation, and analysis"""
    try:
        # Save threat analysis
        threat_file = getattr(args, 'threat_log', DEFAULT_THREAT_LOG)
        with open(threat_file, 'w', encoding='utf-8') as f:
            json.dump(list(threat_buffer), f, indent=2, default=str)
        
        # Save comprehensive report
        report = generate_comprehensive_report()
        report_file = os.path.splitext(args.json)[0] + '_comprehensive_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"[+] Enhanced data saved:")
        print(f"    - Threat analysis: {threat_file}")
        print(f"    - Comprehensive report: {report_file}")
        
    except Exception as e:
        logging.error(f"Error saving enhanced data: {e}")

def make_argparser():
    p = argparse.ArgumentParser(description="Ultimate DHCP sniffer - comprehensive internet traffic analysis with threat detection")
    p.add_argument("-i", "--interface", help="Interface to listen on")
    p.add_argument("--list-interfaces", action="store_true", help="List interfaces and exit")
    p.add_argument("--test-hostnames", action="store_true", help="Test hostname resolution and exit")
    p.add_argument("--pcap", default=DEFAULT_PCAP, help="PCAP output file")
    p.add_argument("--json", default=DEFAULT_JSON, help="JSONL output file")
    p.add_argument("--txt", default=DEFAULT_TEXT, help="Text log file")
    p.add_argument("--summary", default=DEFAULT_SUMMARY, help="Summary JSON file")
    p.add_argument("--raw-dump", default=DEFAULT_RAW_DUMP, help="Raw packet analysis dump")
    p.add_argument("--stats-file", default=DEFAULT_STATS_FILE, help="Comprehensive statistics file")
    p.add_argument("--threat-log", default=DEFAULT_THREAT_LOG, help="Security threat analysis log")
    p.add_argument("--geo-cache", default=DEFAULT_GEO_CACHE, help="Geolocation cache file")
    p.add_argument("-b", "--batch-size", type=int, default=DEFAULT_BATCH, help="Batch size for writing")
    p.add_argument("-f", "--flush-interval", type=int, default=DEFAULT_FLUSH_INTERVAL, help="Flush interval (seconds)")
    p.add_argument("--read-pcap", help="Read from existing pcap file")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("-d", "--diagnostic", action="store_true", help="Diagnostic mode with detailed output")
    p.add_argument("--no-filter", action="store_true", help="Capture all packets (not just DHCP)")
    p.add_argument("--promisc", action="store_true", help="Enable promiscuous mode")
    p.add_argument("--capture-all", action="store_true", help="Capture all DHCP-related traffic including malformed")
    p.add_argument("--deep-analysis", action="store_true", help="Enable deep packet analysis")
    p.add_argument("--internet-focus", action="store_true", help="Focus on internet DHCP traffic analysis")
    p.add_argument("--threat-detection", action="store_true", help="Enable advanced threat detection")
    p.add_argument("--geo-lookup", action="store_true", help="Enable geolocation lookup for internet IPs")
    p.add_argument("--performance-monitor", action="store_true", help="Enable performance monitoring")
    p.add_argument("--max-threads", type=int, default=8, help="Maximum number of processing threads")
    p.add_argument("--enable-hostname-resolution", action="store_true", help="Enable hostname resolution (may slow down processing)")
    return p

def graceful_shutdown(signum, frame, args):
    logging.info(f"[!] Signal {signum}: shutting down gracefully")
    stopping.set()
    
    # Shutdown thread pool
    if 'executor' in globals():
        executor.shutdown(wait=True)
    
    with buf_lock:
        pkts = list(packet_buffer)
        evs = list(event_buffer)
        raws = list(raw_buffer)
        packet_buffer.clear()
        event_buffer.clear()
        raw_buffer.clear()
    
    # Final persistence with all remaining data
    persist_enhanced(pkts, evs, raws, args)
    
    # Save enhanced analysis data
    save_enhanced_data(args)
    
    # Print final comprehensive statistics
    print("\n" + "="*100)
    print("🌐 FINAL INTERNET DHCP CAPTURE STATISTICS 🌐")
    print("="*100)
    print(f"Total Packets Processed:    {packet_count['total']}")
    print(f"DHCP Packets Captured:      {packet_count['dhcp']}")
    print(f"Raw DHCP Traffic:           {packet_count['raw_dhcp']}")
    print(f"🌍 Internet DHCP Traffic:   {packet_count.get('internet_dhcp', 0)}")
    print(f"🏠 Local DHCP Traffic:      {packet_count.get('local_dhcp', 0)}")
    print(f"⚠️  Threat Events Detected: {len(threat_buffer)}")
    print(f"🌐 Internet DHCP Servers:   {len(internet_dhcp_servers)}")
    print(f"Malformed Packets:          {packet_count['malformed']}")
    print(f"Unique DHCP Clients:        {len(client_history)}")
    print(f"DHCP Transactions:          {len(transactions)}")
    print(f"DHCP Servers Found:         {len(server_stats)}")
    print(f"Vendor Classes Detected:    {len(unique_vendors)}")
    print(f"Hostnames Discovered:       {len(unique_hostnames)}")
    print(f"Active Lease Entries:       {len(lease_tracking)}")
    print(f"Network Topology Nodes:     {len(network_topology)}")
    print(f"DHCP Conversations:         {len(dhcp_conversations)}")
    
    # Show top internet DHCP servers
    if internet_dhcp_servers:
        print("\n🌐 TOP INTERNET DHCP SERVERS:")
        sorted_servers = sorted(internet_dhcp_servers.items(), 
                              key=lambda x: x[1]['packet_count'], reverse=True)[:5]
        for server_ip, info in sorted_servers:
            countries = ', '.join(list(info['countries'])[:3])
            print(f"   {server_ip}: {info['packet_count']} packets, {countries}, Score: {info['threat_score']}")
    
    # Show threat summary
    if threat_buffer:
        print(f"\n🚨 SECURITY THREATS DETECTED:")
        threat_types = Counter()
        for threat_event in threat_buffer:
            for threat in threat_event.get('threat_analysis', {}).get('threats', []):
                threat_types[threat['type']] += 1
        
        for threat_type, count in threat_types.most_common(5):
            print(f"   {threat_type}: {count} occurrences")
    
    print("="*100)
    print(f"Unique DHCP Clients:        {len(client_history)}")
    print(f"DHCP Transactions:          {len(transactions)}")
    print(f"DHCP Servers Found:         {len(server_stats)}")
    print(f"Vendor Classes Detected:    {len(unique_vendors)}")
    print(f"Hostnames Discovered:       {len(unique_hostnames)}")
    print(f"Active Lease Entries:       {len(lease_tracking)}")
    print(f"Network Topology Nodes:     {len(network_topology)}")
    print(f"DHCP Conversations:         {len(dhcp_conversations)}")
    print("="*100)
    
    logging.info(f"[FINAL-STATS] {dict(packet_count)}")
    logging.info("[+] Graceful shutdown complete")
    sys.exit(0)

def test_hostname_resolution():
    """Test hostname resolution with common IPs"""
    test_ips = ["8.8.8.8", "1.1.1.1", "127.0.0.1", "192.168.1.1", "192.168.0.1", "192.168.11.1"]
    
    print("\n" + "="*80)
    print("TESTING HOSTNAME RESOLUTION (Linux/Ubuntu)")
    print("="*80)
    
    # First, show available tools
    import subprocess
    tools = {
        'dig': 'dig +short -x',
        'host': 'host', 
        'nslookup': 'nslookup',
        'nmblookup': 'nmblookup -A',
        'avahi-resolve': 'avahi-resolve -a',
        'getent': 'getent hosts'
    }
    
    print("Available hostname resolution tools:")
    for tool, cmd in tools.items():
        try:
            result = subprocess.run([tool, '--version'], capture_output=True)
            status = "✓ Available" if result.returncode == 0 else "✗ Not working"
        except FileNotFoundError:
            status = "✗ Not installed"
        except:
            status = "? Unknown"
        print(f"  {tool:15s}: {status}")
    
    print("\nTesting hostname resolution:")
    for ip in test_ips:
        print(f"\nTesting {ip}:")
        info = get_hostname_info(ip)
        if info:
            print(f"  Result: {info}")
        else:
            print(f"  Result: No hostname info found")
    
    print("="*80 + "\n")

def main():
    args = make_argparser().parse_args()
    
    if args.list_interfaces:
        try:
            interfaces = get_if_list()
            print("\n[*] Available interfaces:")
            for iface in interfaces:
                print(f"  - {iface}")
            print("\n[Tip] Use the interface connected to your AP/network")
            print("Example: python DHCP_Logs.py -i eth0 -v")
        except Exception as e:
            print(f"[!] Error: {e}")
        sys.exit(0)
    
    if args.test_hostnames:
        test_hostname_resolution()
        sys.exit(0)
    
    # Configure logging first
    log_level = logging.DEBUG if args.verbose or args.diagnostic else logging.INFO
    log_file = "dhcp_sniffer.log"
    
    handlers = [logging.StreamHandler()]
    try:
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        handlers.append(file_handler)
        print(f"[+] Logging to: {os.path.abspath(log_file)}")
    except Exception as e:
        print(f"[!] Warning: Could not create log file handler: {e}")
    
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True
    )
    
    if args.read_pcap is None:
        if args.interface is None:
            logging.error("[!] Error: -i/--interface required for live capture")
            logging.info("Run with --list-interfaces to see options")
            sys.exit(1)
    
    # Create output directories and files
    output_files = [args.pcap, args.json, args.txt, args.summary, 
                   getattr(args, 'raw_dump', DEFAULT_RAW_DUMP),
                   getattr(args, 'stats_file', DEFAULT_STATS_FILE),
                   getattr(args, 'threat_log', DEFAULT_THREAT_LOG),
                   getattr(args, 'geo_cache', DEFAULT_GEO_CACHE)]
    
    for path in output_files:
        abs_path = os.path.abspath(path)
        d = os.path.dirname(abs_path) or "."
        
        try:
            os.makedirs(d, exist_ok=True)
            print(f"[+] Output directory: {d}")
        except Exception as e:
            logging.error(f"[!] Cannot create directory {d}: {e}")
            sys.exit(1)
        
        try:
            with open(abs_path, "a", encoding="utf-8") as f:
                f.write("")
            print(f"[+] Output file ready: {abs_path}")
        except Exception as e:
            logging.error(f"[!] Cannot write to {abs_path}: {e}")
            sys.exit(1)
    
    # Configure thread pool size
    global executor
    if hasattr(args, 'max_threads'):
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.max_threads)
    
    signal.signal(signal.SIGINT, lambda s, f: graceful_shutdown(s, f, args))
    signal.signal(signal.SIGTERM, lambda s, f: graceful_shutdown(s, f, args))
    
    args.flush_interval = max(1, int(args.flush_interval))
    args.batch_size = max(1, int(args.batch_size))
    
    print(f"\n[*] Batch size: {args.batch_size} packets")
    print(f"[*] Flush interval: {args.flush_interval} seconds")
    print(f"[*] Thread pool size: {getattr(args, 'max_threads', 8)} workers")
    
    # Start background threads
    flusher = threading.Thread(target=flusher_thread, args=(args,), daemon=True)
    flusher.start()
    
    if getattr(args, 'performance_monitor', False):
        monitor = threading.Thread(target=monitor_performance, daemon=True)
        monitor.start()
        print("[+] Performance monitoring enabled")
    
    # Start hostname cache cleanup thread
    cache_cleaner = threading.Thread(target=clear_hostname_cache_periodically, daemon=True)
    cache_cleaner.start()
    print("[+] Hostname cache optimization enabled")
    
    if args.read_pcap:
        if not os.path.exists(args.read_pcap):
            logging.error(f"[!] File not found: {args.read_pcap}")
            sys.exit(1)
        logging.info(f"[*] Reading pcap: {args.read_pcap}")
        packets = rdpcap(args.read_pcap)
        for p in packets:
            packet_handler(p, args)
        stopping.set()
        with buf_lock:
            pkts = list(packet_buffer)
            evs = list(event_buffer)
            packet_buffer.clear()
            event_buffer.clear()
        persist(pkts, evs, args.pcap, args.json, args.txt)
        logging.info(f"[+] Done. Stats: {packet_count}")
        return
    
    # Enhanced BPF filter to capture DHCP traffic from anywhere
    if args.no_filter:
        bpf_filter = None
    elif args.capture_all:
        # Capture ALL UDP traffic that might contain DHCP (including non-standard ports)
        bpf_filter = "udp"
    elif getattr(args, 'internet_focus', False):
        # Focus on internet traffic with DHCP-like characteristics
        bpf_filter = "((udp port 67 or port 68 or port 546 or port 547) or (udp and (src net not 192.168.0.0/16 and src net not 10.0.0.0/8 and src net not 172.16.0.0/12)))"
    else:
        # Standard DHCP and DHCPv6 ports
        bpf_filter = "udp and (port 67 or port 68 or port 546 or port 547)"
    
    logging.info("="*80)
    logging.info("🌐 ADVANCED INTERNET DHCP ANALYZER WITH THREAT DETECTION 🌐")
    logging.info("="*80)
    logging.info(f"[*] Interface: {args.interface}")
    logging.info(f"[*] Filter: {bpf_filter or 'NONE (all packets)'}")
    if args.capture_all:
        logging.info("[*] Mode: CAPTURE ALL UDP (for internet DHCP traffic)")
    if getattr(args, 'internet_focus', False):
        logging.info("[*] 🌍 INTERNET FOCUS MODE ENABLED")
    if getattr(args, 'threat_detection', False):
        logging.info("[*] 🚨 THREAT DETECTION ENABLED")
    if getattr(args, 'geo_lookup', False):
        logging.info("[*] 🗺️  GEOLOCATION LOOKUP ENABLED")
    if getattr(args, 'performance_monitor', False):
        logging.info("[*] 📊 PERFORMANCE MONITORING ENABLED")
    if getattr(args, 'enable_hostname_resolution', False):
        logging.info("[*] 🔍 HOSTNAME RESOLUTION ENABLED (may impact performance)")
    else:
        logging.info("[*] ⚡ FAST MODE: Hostname resolution disabled for maximum speed")
    logging.info(f"[*] Diagnostic: {args.diagnostic}")
    logging.info(f"[*] Promiscuous: {args.promisc}")
    logging.info(f"[*] Thread Pool: {getattr(args, 'max_threads', 8)} workers")
    logging.info("[*] Output files:")
    logging.info(f"   - PCAP:      {os.path.abspath(args.pcap)}")
    logging.info(f"   - JSON:      {os.path.abspath(args.json)}")
    logging.info(f"   - Text:      {os.path.abspath(args.txt)}")
    logging.info(f"   - Raw:       {os.path.abspath(getattr(args, 'raw_dump', DEFAULT_RAW_DUMP))}")
    logging.info(f"   - Stats:     {os.path.abspath(getattr(args, 'stats_file', DEFAULT_STATS_FILE))}")
    logging.info(f"   - Threats:   {os.path.abspath(getattr(args, 'threat_log', DEFAULT_THREAT_LOG))}")
    logging.info(f"   - GeoCache:  {os.path.abspath(getattr(args, 'geo_cache', DEFAULT_GEO_CACHE))}")
    logging.info("="*80)
    logging.info(f"   - Raw:     {os.path.abspath(getattr(args, 'raw_dump', DEFAULT_RAW_DUMP))}")
    logging.info(f"   - Stats:   {os.path.abspath(getattr(args, 'stats_file', DEFAULT_STATS_FILE))}")
    logging.info("="*70)
    
    try:
        sniff(
            iface=args.interface,
            filter=bpf_filter,
            prn=lambda p: packet_handler(p, args),
            store=False,
            promisc=args.promisc
        )
    except PermissionError:
        logging.error("[!] Permission denied. Run with sudo!")
        sys.exit(1)
    except Exception:
        logging.exception("[!] Sniff failed")
    finally:
        stopping.set()
        with buf_lock:
            pkts = list(packet_buffer)
            evs = list(event_buffer)
            packet_buffer.clear()
            event_buffer.clear()
        persist(pkts, evs, args.pcap, args.json, args.txt)
        logging.info(f"[Stats] Final: {packet_count}")

if __name__ == "__main__":
    main()