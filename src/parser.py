import sys
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
import matplotlib.pyplot as plt
from collections import Counter
import os

def extract_to_dataframe(pcap_file):
    packets = rdpcap(pcap_file)
    data = []

    for pkt in packets:
        if IP in pkt:
            info = {
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "size": len(pkt),
                "sport": pkt.sport if (TCP in pkt or UDP in pkt) else None,
                "dport": pkt.dport if (TCP in pkt or UDP in pkt) else None,
            }
            data.append(info)

    return pd.DataFrame(data)
def protocol_statistics(df):
    print("\n[*] Protocol Statistics:")

    tcp_count = len(df[df['proto'] == 6])
    udp_count = len(df[df['proto'] == 17])
    icmp_count = len(df[df['proto'] == 1])

    print(f"TCP packets : {tcp_count}")
    print(f"UDP packets : {udp_count}")
    print(f"ICMP packets : {icmp_count}")
def detect_port_scan(df, threshold=20):
    print("\n[!] Checking for port scanning...")

    scans = df.groupby("src")["dport"].nunique()
    suspicious = scans[scans > threshold]

    if not suspicious.empty:
        for ip, count in suspicious.items():
            print(f"⚠️ Suspicious IP {ip} scanned {count} ports")
    else:
        print("✅ No port scanning detected")

def plot_top_ips(df):
    os.makedirs("../data", exist_ok=True)

    df["src"].value_counts().head(5).plot(kind="bar")
    plt.title("Top IPs")
    plt.savefig("../data/traffic_chart.png")

    print("[+] Chart saved in data/traffic_chart.png")


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python3 parser.py <pcap_file>")
        exit()

    pcap_path = sys.argv[1]

    print("[+] Loading:", pcap_path)

    try:
        df = extract_to_dataframe(pcap_path)

        if df.empty:
            print("No packets found")
            exit()

        print("\n[*] Sample data:")
        print(df.head())

        detect_port_scan(df)
        protocol_statistics(df)
        plot_top_ips(df)

        df.to_csv("../data/analysis_results.csv", index=False)
        print("[+] Results saved")

    except Exception as e:
        print("[!] Error:", e)




