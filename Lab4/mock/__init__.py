import logging

# Scapy warns about a missing libpcap provider on import; reading pcap files doesn't need one.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
