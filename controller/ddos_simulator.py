#!/usr/bin/env python3
# Script untuk menyimulasikan serangan di jaringan Mininet
import os
import time
import sys
import subprocess
from threading import Thread

def display_banner():
    """Tampilkan banner aplikasi"""
    banner = """
    =======================================================
    |  SDN Anomaly Detection - Attack Simulator          |
    |  Untuk pengujian deteksi anomali                    |
    =======================================================
    """
    print(banner)

def run_command(host, cmd):
    """Jalankan perintah pada host Mininet tertentu"""
    # FIX: Langsung jalankan perintah tanpa menggunakan 'mn -c'
    # karena script ini sudah dijalankan dari dalam host di mininet
    print(f"Running: {cmd}")
    os.system(cmd)
    return True

def generate_normal_traffic(duration=60):
    """Generate normal traffic between hosts"""
    print(f"\n[+] Generating normal traffic for {duration} seconds")

    end_time = time.time() + duration
    while time.time() < end_time:
        # Ping antar host
        run_command(None, f"ping -c 3 10.0.0.2")

        # HTTP request sederhana (perlu httpd pada target)
        try:
            run_command(None, "wget -q -O /dev/null http://10.0.0.4 || true")
        except:
            pass

        # Tunggu interval
        time.sleep(5)

    print("[+] Normal traffic generation completed")

def run_syn_flood(target_host, duration=30):
    """SYN flood attack simulasi"""
    print(f"\n[+] Starting SYN flood against h{target_host} for {duration} seconds")

    # Gunakan hping3 untuk SYN flood
    cmd = f"hping3 -S --flood -V -p 80 10.0.0.{target_host} &"
    run_command(None, cmd)

    # Tunggu durasi serangan
    time.sleep(duration)

    # Terminate attack
    run_command(None, "pkill -f hping3")
    print(f"[+] SYN flood attack completed")

def run_port_scan(target_host):
    """Simulasi port scanning"""
    print(f"\n[+] Starting port scan against h{target_host}")

    # Gunakan nmap untuk port scanning
    cmd = f"nmap -T4 -p 1-1000 10.0.0.{target_host}"
    run_command(None, cmd)

    print(f"[+] Port scan completed")

def run_udp_flood(target_host, duration=30):
    """UDP flood attack simulasi"""
    print(f"\n[+] Starting UDP flood against h{target_host} for {duration} seconds")

    # Gunakan hping3 untuk UDP flood
    cmd = f"hping3 --udp -p 53 --flood 10.0.0.{target_host} &"
    run_command(None, cmd)

    # Tunggu durasi serangan
    time.sleep(duration)

    # Terminate attack
    run_command(None, "pkill -f hping3")
    print(f"[+] UDP flood attack completed")

def attack_menu():
    """Menu untuk memilih jenis serangan"""
    while True:
        print("\n===== Attack Simulation Menu =====")
        print("1. Generate Normal Traffic (60s)")
        print("2. SYN Flood Attack (30s)")
        print("3. UDP Flood Attack (30s)")
        print("4. Port Scan")
        print("5. Full Attack Scenario (All attacks)")
        print("0. Exit")

        choice = input("\nSelect attack type (0-5): ")

        if choice == '1':
            generate_normal_traffic(60)
        elif choice == '2':
            target = input("Enter target host number (1-4): ")
            run_syn_flood(int(target), 30)
        elif choice == '3':
            target = input("Enter target host number (1-4): ")
            run_udp_flood(int(target), 30)
        elif choice == '4':
            target = input("Enter target host number (1-4): ")
            run_port_scan(int(target))
        elif choice == '5':
            print("\n[+] Running full attack scenario...")

            # Run normal traffic (simple version - just a few pings)
            print("Running some normal traffic first...")
            for i in range(5):
                run_command(None, "ping -c 2 10.0.0.2")
                time.sleep(1)

            # Run attacks in sequence
            run_syn_flood(2, 10)
            time.sleep(2)

            run_port_scan(4)
            time.sleep(2)

            run_udp_flood(2, 10)

            print("[+] Full attack scenario completed!")
        elif choice == '0':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    display_banner()

    # Simplified check if running in Mininet
    in_mininet = 'TERM' in os.environ and os.environ.get('HOME', '').startswith('/root')
    if not in_mininet:
        print("WARNING: This script is designed to run inside Mininet!")
        if input("Continue anyway? (y/n): ").lower() != 'y':
            sys.exit(1)

    attack_menu()
