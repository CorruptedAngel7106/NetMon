"""Importing default module"""

import os


# Installing Modules..
def system_install():
    print("[NetMon]: Please Wait, Installing Required Modules..")
    if os.path.exists("is_installed.txt"):
        with open("is_installed.txt", "r") as f:
            is_installed = f.read()
            if is_installed == "True":
                print("All Required Modules Already Installed!")
            else:
                with open("requirements.txt", "r") as f:
                    for line in f:
                        try:
                            os.system(f"pip install {line}")
                            os.system("sudo apt-get install nmap")
                        except Exception as e:
                            print(f"Failed to install module: {line}")
                            print(f"Error: {str(e)}")
                    print("All Required Modules Installed Successfully!")
                    with open("is_installed.txt", "w") as f:
                        f.write("True")
                        f.close()


system_install()

# Third-party imports
import sys
from datetime import datetime
from subprocess import Popen, PIPE
from time import sleep
import platform
import socket
import logging
import coloredlogs
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.output.vt100 import FG_ANSI_COLORS
from prompt_toolkit.styles import Style
from ping3 import ping, verbose_ping
from rich import print
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich.theme import Theme
from scapy.all import traceroute, sniff
from pytube import YouTube
from colorama import Fore
from termcolor import colored
import psutil
import pyfiglet
import requests
import whois

"""
NetMon For Android (Termux Version)
"""

# Standard library imports

# Third-party imports

# Local application/library specific imports
# (none in this case)

"""NetMon For Android (Termux Version)/(Ubuntu Version)"""

logging.basicConfig(level=logging.INFO)
coloredlogs.install(level="INFO")


def display_markdown(file_path):
    with open(file_path, "r") as md_file:
        markdown = Markdown(md_file.read())

    console = Console()
    console.print(markdown)


# Use the function

# Importing Required Modules..


# Importing Modules..
# End of Importing Modules..

# Setting up Console to fit android screen..
console = Console(width=100, height=100)

# Setting up Theme for Rich Module..
theme = Theme(
    {
        "info": "blue",
        "warning": "yellow",
        "danger": "red",
        "success": "green",
        "bold": "bold",
        "italic": "italic",
        "underline": "underline",
        "blink": "blink",
    }
)

# Setting up Table for Rich Module..
table = Table(
    title="NetMon", show_lines=True, title_style="bold magenta", title_justify="center"
)

# Setting up Columns for Rich Module..
columns = Columns()

# Setting up Text for Rich Module..
text = Text("NetMon", justify="center", style="bold blue")

# Setting up Panel for Rich Module..
panel = Panel.fit("NetMon", title="NetMon", style="bold red")

# Setting up Progress for Rich Module..
progress = Progress()


# Setting up Animated Text for Rich Module..
def animated_text(text):
    for char in text:
        print(f"{char}", end="", flush=True)
        sleep(0.1)
    print()


# Setting up PyFiglet for Rich Module..
def banner():
    banner = pyfiglet.figlet_format("NetMon", font="slant")
    print(banner)
    logging.info("NetMon - Tools 4 U..")
    logging.warning('Certain Commands Require "sudo" Permission..')
    logging.info("Type help to see all available commands..\n")
    description = str(
        'NetMon+ Is A Network Monitoring Tool For Android (Termux) & Ubuntu. It Provides A Wide Range Of Network Tools Like IP Address, System Information, Ping, Scan, Port Scan, Whois, GeoIP, Traceroute, DNS Lookup, HTTP Headers, TCP Dump, Netstat, YouTube Video Downloader & More..\n'  # noqa
    )
    fit_description = Text(description, justify="center", style="bold green")
    console.print(fit_description)



display_markdown("./description.md")


commands = [
    "help",
    "exit",
    "clear",
    "banner",
    "ip",
    "info",
    "ping",
    "scan",
    "portscan",
    "whois",
    "geoip",
    "traceroute",
    "dnslookup",
    "httpheaders",
    "tcpdump",
    "netstat",
    "yt_v_downloader",
]


class HardCodedCommands:
    def __init__(self, command):
        self.command = command

    def help(self):
        print("NetMon Help Menu")
        helptb = Table()
        helptb.add_column("Command", style="bold blue", justify="center")
        helptb.add_column("Description", style="bold green", justify="center")
        helptb.add_row("help", "Show Help Menu")
        helptb.add_row("exit", "Exit NetMon")
        helptb.add_row("clear", "Clear Screen")
        helptb.add_row("ip", "Show IP Address")
        helptb.add_row("info", "Show System Information")
        helptb.add_row("ping", "Ping Host")
        helptb.add_row("scan", "Scan Host")
        helptb.add_row("portscan", "Scan Ports of Host")
        helptb.add_row("whois", "Get Whois Information of Host")
        helptb.add_row("geoip", "Get GeoIP Information of Host")
        helptb.add_row("traceroute", "Perform Traceroute on Host")
        helptb.add_row("dnslookup", "Perform DNS Lookup on Host")
        helptb.add_row("httpheaders", "Get HTTP Headers of URL")
        helptb.add_row("tcpdump", "Start TCP Dump")
        helptb.add_row("netstat", "Show Network Connections")
        helptb.add_row("yt_v_downloader", "Download YouTube Video & Video Info")
        console.print(helptb)

    def exit(self):
        print("Exiting NetMon..")
        exit()

    def clear(self):
        os.system("clear")

    def banner(self):
        banner()

    def ip(self):
        try:
            ip = socket.gethostbyname(socket.gethostname())
            IPv4 = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]
            PublicIP = requests.get("https://api.ipify.org").text

            IPTB = Table()
            IPTB.add_column("Type", style="bold blue", justify="center")
            IPTB.add_column("IP Address", style="bold green", justify="center")
            IPTB.add_row("Local IP", f"{ip}")
            IPTB.add_row("IPv4", f"{IPv4}")
            IPTB.add_row("Public IP", f"{PublicIP}")
            console.print(IPTB)
        except Exception as e:
            print("Failed to get IP address.")
            print(f"Error: {str(e)}")

    def info(self):
        try:
            progress_bar = Progress()
            progress_bar.start()
            progress_bar.add_task("Getting System Information..")
            sleep(1)
            progress_bar.stop()
            print(f"System Information: {platform.uname()}")
            print(f"System Platform: {platform.platform()}")
            print(f"System Version: {platform.version()}")
            print(f"System Architecture: {platform.architecture()}")
            print(f"System Processor: {platform.processor()}")
            print(f"System Machine: {platform.machine()}")
            print(f"System Node: {platform.node()}")
            print(f"System Release: {platform.release()}")
            print(f"System System: {platform.system()}")
            print(f"System Python Version: {platform.python_version()}")
            print(f"System Python Compiler: {platform.python_compiler()}")
            print(f"System Python Build: {platform.python_build()}")
        except Exception as e:
            print("Failed to get system information.")
            print(f"Error: {str(e)}")

    def ping(self):
        Host = input(f"{Fore.MAGENTA}Enter Host to Ping: {Fore.RESET}")
        try:
            bar = Progress()
            bar.start()
            bar.add_task(f"Pinging {Host}..")
            sleep(1)
            bar.stop()
            delay = ping(Host)
            if delay is None:
                print(f"Host {Host} is Down!")
            else:
                print(f"Host {Host} is Up! Delay: {delay}ms")

            verbose_ping(Host, count=4)
        except Exception as e:
            print(f"Failed to ping host: {Host}")
            print(f"Error: {str(e)}")

    def scan(self):
        Host = input(f"{Fore.MAGENTA}Enter Host: {Fore.RESET}")
        try:
            bar = Progress()
            bar.start()
            bar.add_task(f"Scanning {Host}..")
            sleep(1)
            bar.stop()
            output = Popen(["nmap", Host], stdout=PIPE).communicate()[0]
            print(output)
        except Exception as e:
            print(f"Failed to scan host: {Host}")
            print(f"Error: {str(e)}")

    def portscan(self):
        Host = input(f"{Fore.MAGENTA}Enter Host: {Fore.RESET}")
        try:
            bar = Progress()
            bar.start()
            bar.add_task(f"Scanning Ports of {Host}..")
            sleep(1)
            bar.stop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            for port in range(1, 65535):
                result = sock.connect_ex((Host, port))
                if result == 0:
                    print(f"Port {port} is Open")
                elif result != 0:
                    pass
        except Exception as e:
            print(f"Failed to perform port scan on host: {Host}")
            print(f"Error: {str(e)}")

    def whois(self):
        Host = input(f"{Fore.MAGENTA}Enter Host: {Fore.RESET}")
        try:
            bar = Progress()
            bar.start()
            bar.add_task(f"Getting Whois Information of {Host}..")
            sleep(1)
            bar.stop()
            whois_info = whois.whois(Host)
            print(whois_info)
        except Exception as e:
            print(f"Failed to get Whois information for host: {Host}")
            print(f"Error: {str(e)}")

    def geoip(self):
        Host = input(f"{Fore.MAGENTA}Enter Host: {Fore.RESET}")
        try:
            bar = Progress()
            bar.start()
            bar.add_task(f"Getting GeoIP Information of {Host}..")
            sleep(1)
            bar.stop()
            response = requests.get(
                f"https://geolocation-db.com/json/{Host}&position=true"
            ).json()
            print(response)
        except Exception as e:
            print(f"Failed to get GeoIP information for host: {Host}")
            print(f"Error: {str(e)}")

    def traceroute(self):
        Host = input(f"{Fore.MAGENTA}Enter Host: {Fore.RESET}")
        try:
            bar = Progress()
            bar.start()
            bar.add_task(f"Tracerouting {Host}..")
            sleep(1)
            bar.stop()

            res, unans = traceroute(Host, maxttl=20)

            res.show()
        except Exception as e:
            print(f"Failed to perform traceroute on host: {Host}")
            print(f"Error: {str(e)}")

    def dnslookup(self):
        Host = input(f"{Fore.MAGENTA}Enter Host {Fore.RESET}")
        try:
            bar = Progress()
            bar.start()
            bar.add_task(f"Looking Up DNS of {Host}..")
            sleep(1)
            bar.stop()
            ip = socket.gethostbyname(Host)
            tb = Table()
            tb.add_column("Host", [Host])
            tb.add_column("IP Address", [ip])
            console.print(tb)
        except Exception as e:
            print(f"Failed to perform DNS lookup for host: {Host}")
            print(f"Error: {str(e)}")

    def httpheaders(self):
        URL = input(f"{Fore.MAGENTA}Enter URL: {Fore.RESET}")
        try:
            bar = Progress()
            bar.start()
            bar.add_task(f"Getting HTTP Headers of {URL}..")
            sleep(1)
            bar.stop()
            response = requests.get(URL)
            headers = response.headers
            print(headers)
        except Exception as e:
            print(f"Failed to get HTTP headers for URL: {URL}")
            print(f"Error: {str(e)}")

    def tcpdump(self):
        try:
            bar = Progress()
            bar.start()
            bar.add_task("Starting TCP Dump..")
            sleep(1)
            bar.stop()

            packets = sniff(filter="tcp", count=10)

            for packet in packets:
                packet.show()
        except Exception as e:
            print("Failed to start TCP dump.")
            print(f"Error: {str(e)}")

    def netstat(self):
        try:
            netstat = psutil.net_connections()
            print(netstat)
        except Exception as e:
            print("Failed to get network connections.")
            print(f"Error: {str(e)}")

    def yt_v_downloader(self):
        URL = input(f"{Fore.MAGENTA}Enter YouTube Video URL: {Fore.RESET}")
        try:
            yt = YouTube(URL)
            print(f"Title: {yt.title}")
            print(f"Views: {yt.views}")
            print(f"Length: {yt.length} seconds")
            print(f"Rating: {yt.rating}")
            print(f"Description: {yt.description}")
            print(f"Thumbnail: {yt.thumbnail_url}")
            print(f"Streams: {yt.streams}")
            stream = yt.streams.get_highest_resolution()
            stream.download()
        except Exception as e:
            print(f"Failed to download YouTube video from URL: {URL}")
            print(f"Error: {str(e)}")


style = Style.from_dict(
    {
        "prompt": "#800080",  # Hexadecimal color code for purple
    }
)


def main():
    banner()
    while True:
        command = prompt(
            "Enter Your Command: ",
            completer=WordCompleter(
                [
                    "help",
                    "exit",
                    "clear",
                    "ip",
                    "info",
                    "ping",
                    "scan",
                    "portscan",
                    "whois",
                    "geoip",
                    "traceroute",
                    "dnslookup",
                    "httpheaders",
                    "tcpdump",
                    "netstat",
                ]
            ),
            style=style,
            complete_while_typing=True,
            complete_in_thread=True,
            complete_style="fg:ansiblue",
        )
        if command in [
            "help",
            "exit",
            "clear",
            "banner",
            "ip",
            "info",
            "ping",
            "scan",
            "portscan",
            "whois",
            "geoip",
            "traceroute",
            "dnslookup",
            "httpheaders",
            "tcpdump",
            "netstat",
            "yt-v-downloader",
        ]:
            hc = HardCodedCommands(command)
            try:
                if command.startswith("help"):
                    logging.debug("Running Help Command..")
                    hc.help()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("exit"):
                    logging.debug("Running Exit Command..")
                    hc.exit()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("clear"):
                    logging.debug("Running Clear Command..")
                    hc.clear()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("ip"):
                    logging.debug("Running IP Command..")
                    hc.ip()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("banner"):
                    logging.debug("Running Info Command..")
                    hc.info()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("ping"):
                    logging.debug("Running Ping Command..")
                    hc.ping()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("scan"):
                    logging.debug("Running Scan Command..")
                    hc.scan()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("portscan"):
                    logging.debug("Running Port Scan Command..")
                    hc.portscan()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("whois"):
                    logging.debug("Running Whois Command..")
                    hc.whois()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("geoip"):
                    logging.debug("Running GeoIP Command..")
                    hc.geoip()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command.startswith("traceroute"):
                    logging.debug("Running Traceroute Command..")
                    hc.traceroute()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command == "dnslookup":
                    logging.debug("Running DNS Lookup Command..")
                    hc.dnslookup()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command == "httpheaders":
                    logging.debug("Running HTTP Headers Command..")
                    hc.httpheaders()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command == "tcpdump":
                    logging.debug("Running TCP Dump Command..")
                    hc.tcpdump()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command == "netstat":
                    logging.debug("Running Netstat Command..")
                    hc.netstat()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                elif command == "yt_v_downloader":
                    logging.debug("Running YouTube Video Downloader Command..")
                    hc.yt_v_downloader()
                    finished_input = input("Press Enter To Continue..")
                    if finished_input == "":
                        os.system("cls" if os.name == "nt" else "clear")
                else:
                    print("Invalid Command!")
            except Exception as e:
                print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    try:
        os.system("cls" if os.name == "nt" else "clear")

        while True:
            main()
    except KeyboardInterrupt:
        print("Exiting NetMon..")
        exit()
