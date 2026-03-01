from scapy.all import sniff, get_if_addr, IP, UDP, DNS, DNSQR, DNSRR, sendp, conf
import time, subprocess

# ==========================================
# 1. CONFIGURATION
# ==========================================
IFACE_HOTSPOT = "bridge101" # macOS Hotspot Bridge
IFACE_INTERNET = "en0"      # macOS Internet Source (Wi-Fi or Ethernet)

MAX_BANDWIDTH_MBPS = 8000    # Reset to your original 2 Mbps requirement
CLOUDFLARE_DNS = "1.1.1.1"

# Automatically detect your Mac's IP to avoid routing yourself
MY_IP = get_if_addr(IFACE_HOTSPOT)
print(f"[*] Gateway IP detected: {MY_IP} (Traffic from this IP will be ignored)")

# Custom Enterprise Records
CUSTOM_DNS_RECORDS = {
    b"levis-portal.local.": "10.0.0.1",
    b"school-project.test.": "192.168.1.99"
}

dns_table = {}

# ==========================================
# 2. BANDWIDTH LIMITER (Token Bucket)
# ==========================================
class TokenBucketLimiter:
    def __init__(self, limit_mbps):
        self.limit_bytes_per_sec = (limit_mbps * 1024 * 1024) / 8
        self.bucket = self.limit_bytes_per_sec
        self.last_check = time.time()

    def allow(self, packet_size):
        now = time.time()
        elapsed = now - self.last_check
        self.last_check = now
        
        self.bucket += elapsed * self.limit_bytes_per_sec
        if self.bucket > self.limit_bytes_per_sec:
            self.bucket = self.limit_bytes_per_sec
            
        if self.bucket >= packet_size:
            self.bucket -= packet_size
            return True
        return False

limiter = TokenBucketLimiter(MAX_BANDWIDTH_MBPS)

# ==========================================
# 3. OUTBOUND LOGIC (Hotspot -> Internet)
# ==========================================
def handle_outbound(pkt):
    if not pkt.haslayer(IP):
        return pkt

    # Ignore traffic from your own Mac
    if pkt[IP].src == MY_IP:
        return pkt

    # Apply 2 Mbps Limit
    if not limiter.allow(len(pkt)):
        return None

    # DNS Interception
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[UDP].dport == 53:
        qname = pkt[DNSQR].qname
        
        # Scenario A: Custom Enterprise Record
        if qname in CUSTOM_DNS_RECORDS:
            target_ip = CUSTOM_DNS_RECORDS[qname]
            reply = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=qname, ttl=10, rdata=target_ip))
            sendp(reply, iface=IFACE_HOTSPOT, verbose=0)
            print(f"[*] Custom DNS: {qname.decode()} -> {target_ip}")
            return None 
            
        # Scenario B: Force Cloudflare
        state_key = (pkt[IP].src, pkt[UDP].sport, pkt[DNS].id)
        dns_table[state_key] = pkt[IP].dst # Remember original intended DNS

        pkt[IP].dst = CLOUDFLARE_DNS
        del pkt[IP].chksum, pkt[UDP].chksum # Force recalculation
        print(f"[!] DNS Reroute: {qname.decode()} -> {CLOUDFLARE_DNS}")

    return pkt

# ==========================================
# 4. INBOUND LOGIC (Internet -> Hotspot)
# ==========================================

def enable_macos_routing():
    print("[*] Configuring macOS Kernel for Routing...")
    try:
        # 1. Enable IP Forwarding in the kernel
        subprocess.run(["sudo", "sysctl", "-w", "net.inet.ip.forwarding=1"], check=True)
        
        # 2. Trigger the 'sharing' check (This mimics the GUI toggle)
        # Note: This doesn't start the SSID broadcast, but it opens the gates
        print("[+] IP Forwarding Enabled.")
        
    except Exception as e:
        print(f"[!] Could not auto-configure routing: {e}")
        print("[!] Please ensure you run this with sudo!")

def handle_inbound(pkt):
    if not pkt.haslayer(IP):
        return pkt

    # Reverse DNS Translation (NAT Logic)
    if pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt[UDP].sport == 53:
        state_key = (pkt[IP].dst, pkt[UDP].dport, pkt[DNS].id)
        if state_key in dns_table:
            # Change the source back to what the guest expected
            pkt[IP].src = dns_table.pop(state_key)
            del pkt[IP].chksum, pkt[UDP].chksum

    return pkt

def bridge_loop(pkt):
    try:
        if pkt.sniffed_on == IFACE_HOTSPOT:
            out_pkt = handle_outbound(pkt)
            if out_pkt:
                sendp(out_pkt, iface=IFACE_INTERNET, verbose=0)
        elif pkt.sniffed_on == IFACE_INTERNET:
            in_pkt = handle_inbound(pkt)
            if in_pkt:
                sendp(in_pkt, iface=IFACE_HOTSPOT, verbose=0)
    except Exception:
        pass

# ==========================================
# 5. MAIN EXECUTION
# ==========================================
def main():
    conf.use_pcap = True # Required for macOS stability
    print("==================================================")
    print("🚀 LEVI'S WIFI RELAY ACTIVE")
    print(f"📡 Bridging: {IFACE_HOTSPOT} <---> {IFACE_INTERNET}")
    print(f"🚦 Limit: {MAX_BANDWIDTH_MBPS} Mbps | DNS: {CLOUDFLARE_DNS}")
    print("==================================================")
    
    try:
        sniff(iface=[IFACE_HOTSPOT, IFACE_INTERNET], prn=bridge_loop, store=False)
    except KeyboardInterrupt:
        print("\nStopping...")

if __name__ == "__main__":
    main()