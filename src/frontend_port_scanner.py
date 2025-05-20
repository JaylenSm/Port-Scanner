from scapy.all import IP, UDP, TCP, ICMP, sr1
import time
import socket
import threading
import ssl
from random import randint
import select
import os 
import platform
from backend_port_scanner import *

target_host = None
host = None
port = None


def main():
    global target_host
    global host
    global port
    print("""
           Welcome to a CLI-based port scanner!
           This tool will help you scan ports on a target host.
           Ping the target host to check if it's reachable.
           And banner grab ports to identify services running on them.
           [Enter nothing to start or any key to exit the program.]""")
    user_input = input(">>> ")
    user_input = user_input[:10]
    user_input = user_input.replace(" ", "")
    user_input = user_input.replace("\n", "")
    user_input = user_input.lower()
    if user_input == '':
        print("Starting the program...")
        time.sleep(2)
        clear_terminal()
        start = True
        while start == True:
            while True:
                host_name = input("\nEnter the target host (IP or domain): ")
                host_name = host_name[:30]
                host_name = host_name.replace(" ", "")
                host_name = host_name.replace("\n", "")
                host_name = host_name.lower()
                if host_name == '':
                    print("\nHost cannot be empty. Please try again.\n")
                    time.sleep(2)
                    clear_terminal()
                    continue
                try:
                    print(f"\nChecking if {host_name} is legit!\n")
                    host_ip = socket.gethostbyname(host_name) # Checks if host is legit and reachable
                    print(f"\nThe host is legit!\nHost IP: {host_ip}\n")
                    host = host_name
                    break
                except socket.gaierror:
                    print(f"\nInvalid host: {host_name}. Please enter a valid IP address or domain name.\n")
                    time.sleep(2)
                    clear_terminal()
                    continue
            while True:
                lower_port = input("\nEnter the lower port range or enter nothing for the default! (default: 1): ")
                lower_port = lower_port[:5]
                lower_port = lower_port.replace(" ", "")
                lower_port = lower_port.replace("\n", "")
                try:
                    if lower_port != '':
                        type(int(lower_port))
                except ValueError:
                    print("\nInvalid input. Please enter a valid port number.\n")
                    time.sleep(2)
                    clear_terminal()
                    continue
                if lower_port == '':
                    lower_port = 1
                    print("\nDefaulting to 1...\n")
                    time.sleep(2)
                    clear_terminal()
                elif int(lower_port) < 1 or int(lower_port) > 65535:
                    print("\nPort number must be between 1 and 65535. Please try again.\n")
                    time.sleep(2)
                    clear_terminal()
                    continue
                upper_port = input("\nEnter the upper port range or enter nothing for the default! (default: 100): ")
                upper_port = upper_port[:5]
                upper_port = upper_port.replace(" ", "")
                upper_port = upper_port.replace("\n", "")
                try:
                    if upper_port != '':
                        type(int(upper_port))
                except ValueError:
                    print("\nInvalid input. Please enter a valid port number.\n")
                    time.sleep(2)
                    clear_terminal()
                    continue
                if upper_port == '':
                    upper_port = 100
                    port = (int(lower_port), (int(upper_port)+1))
                    print("\nDefaulting to 100...\n")
                    time.sleep(2)
                    clear_terminal()
                    start = False
                    break
                elif int(upper_port) < 1 or int(upper_port) > 65535:
                    print("\nPort number must be between 1 and 65535. Please try again.\n")
                    time.sleep(2)
                    clear_terminal()
                    continue
                elif int(lower_port) > int(upper_port):
                    print("\nLower port range cannot be greater than upper port range. Please try again.\n")
                    time.sleep(2)
                    clear_terminal()
                    continue
                elif int(lower_port) == int(upper_port):
                    port = (int(lower_port), (int(upper_port)+1))
                    print("\nScanning single port...\n")
                    print(f"\nPort: {lower_port}\n")
                    time.sleep(2)
                    clear_terminal()
                    start = False
                    break
                else:
                    port = (int(lower_port), (int(upper_port)+1))
                    print(f"\nPort range: {lower_port} to {upper_port}\n")
                    time.sleep(2)
                    clear_terminal()
                    start = False
                    break
        
        target_host = PortScanner(host, port)
        while True:
            print(f"\nTarget host: {target_host.host}\nTarget port: {target_host.port[0]}-{(target_host.port[1]-1)}\n")
            user_input = input("""Is this correct? (y/n): 
>>> """)
            user_input = user_input[:1]
            user_input = user_input.replace(" ", "")
            user_input = user_input.replace("\n", "")
            user_input = user_input.lower()
            if user_input == 'y':
                print("\nStarting the scan...\n")
                time.sleep(2)
                clear_terminal()
                break
            elif user_input == 'n':
                print("\nReturning back to main...\n")
                time.sleep(2)
                clear_terminal()
                break
            else:
                print("\nInvalid input. Please enter 'y' or 'n'.\n")
                time.sleep(2)
                clear_terminal()
                continue
        if user_input == 'n':
            main()
        elif user_input == 'y':
            print("""
                  Do you want to scan [T]CP or [U]DP ports or [B]oth? Or [P]ing the host?
                  Press [E] to exit the program or [M] to return to main.
                  To banner grab you will have to scan both protocols.""")
            user_input = input(">>> ")
            user_input = user_input[:1]
            user_input = user_input.replace(" ", "")
            user_input = user_input.replace("\n", "")
            user_input = user_input.lower()
            if user_input == 't':
                tcp_scan()
                time.sleep(2)
                input("\n\nPress Enter to continue...\n\n")
                clear_terminal()
                while True:
                    print("Will you like to return to main? (y/n)")
                    user_input = input(">>> ")
                    user_input = user_input[:1]
                    user_input = user_input.replace(" ", "")
                    user_input = user_input.replace("\n", "")
                    user_input = user_input.lower()
                    if user_input == 'y':
                        print("\nReturning to main...\n")
                        time.sleep(2)
                        clear_terminal()
                        break
                    elif user_input == 'n':
                        print("\nExiting...\n")
                        time.sleep(2)
                        clear_terminal()
                        exit()
                    else:
                        print("\nInvalid input. Please enter 'y' or 'n'.\n")
                        time.sleep(2)
                        clear_terminal()
                        continue
                main()
                main()
            elif user_input == 'u':
                udp_scan()
                time.sleep(2)
                input("\n\nPress Enter to continue...\n\n")
                clear_terminal()
                while True:
                    print("Will you like to return to main? (y/n)")
                    user_input = input(">>> ")
                    user_input = user_input[:1]
                    user_input = user_input.replace(" ", "")
                    user_input = user_input.replace("\n", "")
                    user_input = user_input.lower()
                    if user_input == 'y':
                        print("\nReturning to main...\n")
                        time.sleep(2)
                        clear_terminal()
                        break
                    elif user_input == 'n':
                        print("\nExiting...\n")
                        time.sleep(2)
                        clear_terminal()
                        exit()
                    else:
                        print("\nInvalid input. Please enter 'y' or 'n'.\n")
                        time.sleep(2)
                        clear_terminal()
                        continue
                main()
            elif user_input == 'b':
                scan_both()
                time.sleep(2)
                input("\n\nPress Enter to continue...\n\n")
                clear_terminal()
                while True:
                    print("Will you like to banner grab? (y/n)")
                    user_input = input(">>> ")
                    user_input = user_input[:1]
                    user_input = user_input.replace(" ", "")
                    user_input = user_input.replace("\n", "")
                    user_input = user_input.lower()
                    if user_input == 'y':
                        banner_grab()
                        time.sleep(2)
                        input("\n\nPress Enter to continue...\n\n")
                        clear_terminal()
                        break
                    elif user_input == 'n':
                        print("\nBanner grabbing skipped...\n")
                        time.sleep(2)
                        clear_terminal()
                        break
                    else:
                        print("\nInvalid input. Please enter 'y' or 'n'.\n")
                        time.sleep(2)
                        clear_terminal()
                        continue
                while True:
                    print("Will you like to return to main? (y/n)")
                    user_input = input(">>> ")
                    user_input = user_input[:1]
                    user_input = user_input.replace(" ", "")
                    user_input = user_input.replace("\n", "")
                    user_input = user_input.lower()
                    if user_input == 'y':
                        print("\nReturning to main...\n")
                        time.sleep(2)
                        clear_terminal()
                        break
                    elif user_input == 'n':
                        print("\nExiting...\n")
                        time.sleep(2)
                        clear_terminal()
                        exit()
                    else:
                        print("\nInvalid input. Please enter 'y' or 'n'.\n")
                        time.sleep(2)
                        clear_terminal()
                        continue
                main()
            elif user_input == 'p':
                ping_host()
                time.sleep(2)
                input("\n\nPress Enter to continue...\n\n")
                clear_terminal()
                while True:
                    print("Will you like to return to main? (y/n)")
                    user_input = input(">>> ")
                    user_input = user_input[:1]
                    user_input = user_input.replace(" ", "")
                    user_input = user_input.replace("\n", "")
                    user_input = user_input.lower()
                    if user_input == 'y':
                        print("\nReturning to main...\n")
                        time.sleep(2)
                        clear_terminal()
                        break
                    elif user_input == 'n':
                        print("\nExiting...\n")
                        time.sleep(2)
                        clear_terminal()
                        exit()
                    else:
                        print("\nInvalid input. Please enter 'y' or 'n'.\n")
                        time.sleep(2)
                        clear_terminal()
                        continue
                main()
            elif user_input == 'e':
                print("\nExiting the program...\n")
                time.sleep(2)
                clear_terminal()
                exit()
            elif user_input == 'm':
                print("\nReturning to main...\n")
                time.sleep(2)
                clear_terminal()
                main()
        else:
            print("\nSomething went wrong, returning to main!\n")
            time.sleep(2)
            clear_terminal()
            main()

            


             
    else:
        print("Exiting the program...")
        time.sleep(2)
        clear_terminal()
        exit()

def tcp_scan():
    global target_host
    print(f"\nScanning TCP ports...\n")
    time.sleep(2)
    target_host.tcp_scan()
    print("\nTCP scan completed.\n")

def udp_scan():
    global target_host
    print(f"\nScanning UDP ports...\n")
    time.sleep(2)
    target_host.udp_scan()
    print("\nUDP scan completed.\n")

def ping_host():
    global target_host
    print(f"\nPinging {target_host.host}...\n")
    time.sleep(2)
    target_host.ping_scan()
    print("\nPing scan completed.\n")

def banner_grab():
    global target_host
    print(f"\nGrabbing banners from {target_host.host}...\n")
    time.sleep(2)
    target_host.banner_grabbing()
    print("\nBanner grabbing completed.\n")

def scan_both():
    global target_host
    print(f"\nScanning both TCP and UDP ports...\n")
    time.sleep(2)
    try:
        threaded_tcp_scan = threading.Thread(target=target_host.tcp_scan, args=())
        threaded_udp_scan = threading.Thread(target=target_host.udp_scan, args=())
        threaded_tcp_scan.start()
        threaded_udp_scan.start()
        threaded_tcp_scan.join()
        threaded_udp_scan.join()
        time.sleep(2)
    except Exception as e:
        print(f"\nError occurred while scanning both TCP and UDP ports: {e}\n")
        time.sleep(2)
    print("\nBoth TCP and UDP scans completed.\n")


def clear_terminal():
    # Check the operating system and clear the terminal accordingly
    if platform.system() == "Windows":
        os.system("cls")
    elif platform.system() == "Linux" or platform.system() == "Darwin": # For MacOS and Linux
        os.system("clear")
    else:
        print("\n" * 100) #For unindentified systems to get 100 new lines of code in terminal.
        
if __name__ == "__main__":
    main()