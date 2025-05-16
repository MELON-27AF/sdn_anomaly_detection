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
    full_cmd = f"h{host} {cmd}"
    print(f"Running on h{host}: {cmd}")
    os.system(f"mn -c {full_cmd}")
    return True

def generate_normal_traffic(duration=60):
    """Generate normal traffic between hosts"""
    print(f"\n[+] Generating normal traffic for {duration} seconds")

    end_time = time.time() + duration
    while time.time() < end_time:
        # Ping antar host
        src = 1
        dst = 2
        run_command(src, f"ping -c 3 10.0.0.{dst}")

        # HTTP request sederhana (perlu httpd pada target)
        try:
            run_command(3, "wget -q -O /dev/null http://10.0.0.4")
        except:
            pass

        # Tunggu interval
        time.sleep(5)

    print("[+] Normal traffic generation completed")

def run_syn_flood(target_host, duration=30):
    """SYN flood attack simulasi"""
    print(f"\n[+] Starting SYN flood against h{target_host} for {duration} seconds")

    # Gunakan hping3 untuk SYN flood
    cmd = f"hping3 -S --flood -V -p 80 10.0.0.{target_host}"

    # Jalankan dari host tertentu - menggunakan h1 sebagai attacker
    attacker_host = 1

    # Jalankan dalam background process
    process = subprocess.Popen(f"mn -c h{attacker_host} {cmd}", shell=True)

    # Tunggu durasi serangan
    time.sleep(duration)

    # Terminate attack
    process.terminate()
    print(f"[+] SYN flood attack completed")

def run_port_scan(target_host):
    """Simulasi port scanning"""
    print(f"\n[+] Starting port scan against h{target_host}")

    # Gunakan nmap untuk port scanning
    cmd = f"nmap -T4 -p 1-1000 10.0.0.{target_host}"

    # Jalankan dari host tertentu
    attacker_host = 3
    run_command(attacker_host, cmd)

    print(f"[+] Port scan completed")

def run_udp_flood(target_host, duration=30):
    """UDP flood attack simulasi"""
    print(f"\n[+] Starting UDP flood against h{target_host} for {duration} seconds")

    # Gunakan hping3 untuk UDP flood
    cmd = f"hping3 --udp -p 53 --flood 10.0.0.{target_host}"

    # Jalankan dari host tertentu
    attacker_host = 3

    # Jalankan dalam background process
    process = subprocess.Popen(f"mn -c h{attacker_host} {cmd}", shell=True)

    # Tunggu durasi serangan
    time.sleep(duration)

    # Terminate attack
    process.terminate()
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
            # Background normal traffic
            normal_thread = Thread(target=generate_normal_traffic, args=(180,))
            normal_thread.daemon = True
            normal_thread.start()

            # Wait before starting attacks
            time.sleep(30)

            # Run attacks in sequence
            run_syn_flood(2, 30)
            time.sleep(10)

            run_port_scan(4)
            time.sleep(10)

            run_udp_flood(2, 30)

            print("[+] Full attack scenario completed!")
        elif choice == '0':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    display_banner()

    # Check if running in Mininet
    if 'PYTHONPATH' in os.environ and 'mininet' in os.environ['PYTHONPATH']:
        print("Running inside Mininet environment")
    else:
        print("WARNING: This script is designed to run inside Mininet!")
        if input("Continue anyway? (y/n): ").lower() != 'y':
            sys.exit(1)

    attack_menu()
