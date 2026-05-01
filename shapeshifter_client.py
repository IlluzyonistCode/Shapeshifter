import asyncio
import socket
import ssl
import struct
import hashlib
import hmac
import json
import os
import ipaddress
import logging
import random
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger('shapeshifter.client')

MAX_FRAME_SIZE = 64 * 1024


class Crypto:
    def __init__(self):
        self._private_key = X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self.session_key = None
        self._frame_key = None

    @property
    def public_key_bytes(self):
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def perform_handshake(self, peer_public_key_bytes):
        peer_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)

        shared_secret = self._private_key.exchange(peer_key)

        self.session_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'shapeshifter-v1-data'
        ).derive(shared_secret)

        self._frame_key = HKDF(
            algorithm=hashes.SHA256(), length=16, salt=None,
            info=b'shapeshifter-v1-frame'
        ).derive(shared_secret)

        return self.session_key

    def encrypt(self, plaintext, aad=b''):
        if not self.session_key:
            raise RuntimeError('Session key not established.')

        nonce = os.urandom(12)

        ct = AESGCM(self.session_key).encrypt(nonce, plaintext, aad or None)

        return nonce + ct

    def decrypt(self, data, aad=b''):
        if not self.session_key:
            raise RuntimeError('Session key not established.')

        return AESGCM(self.session_key).decrypt(data[:12], data[12:], aad or None)

    def encrypt_frame_length(self, length):
        mask = hashlib.sha256(self._frame_key).digest()[:4]
        raw = struct.pack('>I', length)

        return bytes(a ^ b for a, b in zip(raw, mask))

    def decrypt_frame_length(self, data):
        mask = hashlib.sha256(self._frame_key).digest()[:4]
        raw = bytes(a ^ b for a, b in zip(data, mask))

        return struct.unpack('>I', raw)[0]


class PacketType:
    HANDSHAKE = 0x01
    DATA = 0x02
    KEEPALIVE = 0x03
    DISCONNECT = 0x04
    ACK = 0x05
    COVER = 0x06


MAGIC = b'\x16\x03\x01'
HEADER_SIZE = 22


def packet_encode(ptype, payload, seq, add_padding=True):
    padding = os.urandom(random.randint(16, 256)) if add_padding else b''
    ts = int(time.time() * 1000)
    header = struct.pack('>3sBIHQI', MAGIC, ptype, len(payload), len(padding), ts, seq)

    return header + payload + padding

def packet_decode(data):
    if len(data) < HEADER_SIZE:
        raise ValueError(f'Packet too short: {len(data)}B')

    magic, ptype, payload_len, padding_len, ts, seq = struct.unpack('>3sBIHQI', data[:HEADER_SIZE])

    if magic != MAGIC:
        raise ValueError(f'Bad magic: {magic!r}')

    payload = data[HEADER_SIZE:HEADER_SIZE + payload_len]

    return ptype, payload, seq


class Sequencer:
    def __init__(self, window=64):
        self._next = 0
        self._last = -1
        self._seen = set()
        self._window = window

    def next_seq(self):
        s = self._next

        self._next = (self._next + 1) % (2 ** 32)

        return s

    def valid(self, seq):
        if seq in self._seen:
            return False

        if seq < self._last - self._window:
            return False

        self._seen.add(seq)

        if len(self._seen) > self._window * 2:
            cutoff = self._last - self._window

            self._seen = {s for s in self._seen if s >= cutoff}

        self._last = max(self._last, seq)

        return True


FAKE_SNI_LIST = [
    'cdn.cloudflare.com',
    'storage.googleapis.com',
    's3.amazonaws.com',
    'ajax.googleapis.com',
    'fonts.googleapis.com',
    'www.gstatic.com'
]


def tls_wrap(data):
    MAX = 16383
    out = bytearray()

    for i in range(0, len(data), MAX):
        chunk = data[i:i + MAX]
        out += struct.pack('>BBBH', 23, 0x03, 0x03, len(chunk)) + chunk

    return bytes(out)

def tls_unwrap(data):
    out = bytearray()
    off = 0

    while off + 5 <= len(data):
        length = struct.unpack('>H', data[off + 3:off + 5])[0]
        out += data[off + 5:off + 5 + length]
        off += 5 + length

    return bytes(out)

def build_tls_client_hello(sni):
    sni_bytes = sni.encode()
    sni_ext = (
        struct.pack('>H', len(sni_bytes) + 5) +
        b'\x00' +
        struct.pack('>H', len(sni_bytes)) +
        sni_bytes
    )
    sni_extension = struct.pack('>HH', 0x0000, len(sni_ext)) + sni_ext

    cipher_suites = bytes([
        0x13, 0x01,
        0x13, 0x02,
        0x13, 0x03,
        0xC0, 0x2B,
        0xC0, 0x2F
    ])

    supported_versions = struct.pack('>HH', 0x002B, 5) + b'\x04\x03\x04\x03\x03'
    groups = bytes([0x00, 0x1D, 0x00, 0x17, 0x00, 0x18])
    supported_groups = struct.pack('>HHH', 0x000A, len(groups) + 2, len(groups)) + groups

    extensions = sni_extension + supported_versions + supported_groups
    body = (
        b'\x03\x03' + os.urandom(32) + b'\x00' +
        struct.pack('>H', len(cipher_suites)) + cipher_suites +
        b'\x01\x00' +
        struct.pack('>H', len(extensions)) + extensions
    )
    handshake = b'\x01' + struct.pack('>I', len(body))[1:] + body

    return struct.pack('>BBBH', 0x16, 0x03, 0x01, len(handshake)) + handshake

async def jitter():
    delay = min(abs(random.gauss(0.005, 0.003)), 0.05)

    if delay > 0:
        await asyncio.sleep(delay)


class Transport:
    def __init__(self, reader, writer, crypto=None):
        self.reader = reader
        self.writer = writer
        self.crypto = crypto
        self._closed = False

    async def send(self, data):
        if self._closed:
            raise ConnectionError('Transport closed')

        if len(data) > MAX_FRAME_SIZE:
            raise ValueError(f'Frame too large: {len(data)}')

        length_bytes = (
            self.crypto.encrypt_frame_length(len(data))
            if self.crypto and self.crypto._frame_key
            else struct.pack('>I', len(data))
        )

        self.writer.write(length_bytes + data)

        await self.writer.drain()

    async def recv(self):
        if self._closed:
            raise ConnectionError('Transport closed')

        raw = await self.reader.readexactly(4)

        length = (
            self.crypto.decrypt_frame_length(raw)
            if self.crypto and self.crypto._frame_key
            else struct.unpack('>I', raw)[0]
        )

        if length > MAX_FRAME_SIZE:
            raise ValueError(f'Frame too large: {length}')

        return await self.reader.readexactly(length) if length else b''

    async def close(self):
        if not self._closed:
            self._closed = True

            try:
                self.writer.close()

                await self.writer.wait_closed()
            except Exception:
                pass

    @property
    def peer(self):
        return self.writer.get_extra_info('peername', ('?', 0))


class ConnectionAuth:
    def __init__(self, psk):
        self._key = psk.encode() if isinstance(psk, str) else psk

    def generate_token(self):
        ts = struct.pack('>Q', int(time.time()))
        nonce = os.urandom(16)
        mac = hmac.new(self._key, ts + nonce, hashlib.sha256).digest()

        return ts + nonce + mac

    def verify_token(self, token, max_age=30):
        if len(token) < 56:
            return False

        ts_bytes, nonce, received_mac = token[:8], token[8:24], token[24:56]
        expected_mac = hmac.new(self._key, ts_bytes + nonce, hashlib.sha256).digest()

        if not hmac.compare_digest(received_mac, expected_mac):
            return False

        age = abs(time.time() - struct.unpack('>Q', ts_bytes)[0])

        return age <= max_age


class CoverTraffic:
    def __init__(self, send_fn, interval_min=5.0, interval_max=30.0):
        self._send = send_fn
        self._min = interval_min
        self._max = interval_max
        self._task = None

    async def start(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self):
        if self._task:
            self._task.cancel()

    async def _loop(self):
        while True:
            await asyncio.sleep(random.uniform(self._min, self._max))

            try:
                await self._send(os.urandom(random.randint(64, 512)))
            except Exception:
                break


DOH_SERVERS = [
    'cloudflare-dns.com',
    'dns.google',
    'dns.quad9.net'
]


class DnsCache:
    def __init__(self):
        self._store = {}

    def get(self, domain):
        entry = self._store.get(domain)

        if not entry:
            return

        ip, expires = entry

        if time.time() > expires:
            del self._store[domain]

            return

        return ip

    def set(self, domain, ip, ttl):
        self._store[domain] = (ip, time.time() + ttl)


class DoHResolver:
    def __init__(self, server=None):
        self.server = server or DOH_SERVERS[0]
        self.cache = DnsCache()

    async def resolve(self, domain, qtype='A'):
        cached = self.cache.get(domain)

        if cached:
            return cached

        for server in DOH_SERVERS:
            try:
                result = await asyncio.wait_for(
                    self._query(server, domain, qtype), timeout=5.0
                )

                if result:
                    return result
            except asyncio.TimeoutError:
                logger.warning(f'DoH timeout: {server}')
            except Exception as e:
                logger.warning(f'DoH error ({server}): {e}')

        logger.error(f'Failed to resolve: {domain}')

    async def _query(self, server, domain, qtype='A'):
        path = f'/dns-query?name={domain}&type={qtype}'
        request = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {server}\r\n'
            f'Accept: application/dns-json\r\n'
            f'Connection: close\r\n\r\n'
        ).encode()

        ctx = ssl.create_default_context()

        reader, writer = await asyncio.open_connection(server, 443, ssl=ctx)

        try:
            writer.write(request)

            await writer.drain()

            raw = b''

            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)

                if not chunk:
                    break

                raw += chunk

                if len(raw) > 65536:
                    break
        finally:
            writer.close()

        return self._parse(raw, domain)

    def _parse(self, raw, domain):
        try:
            if b'\r\n\r\n' not in raw:
                return

            _, body = raw.split(b'\r\n\r\n', 1)
            body_str = body.decode('utf-8', errors='ignore').strip()

            if body_str and body_str[0] in '0123456789abcdefABCDEF':
                lines = body_str.split('\r\n')
                body_str = lines[1] if len(lines) >= 2 else body_str

            import json as _json

            data = _json.loads(body_str)

            if data.get('Status') != 0:
                return

            for answer in data.get('Answer', []):
                if answer.get('type') == 1:
                    ip = answer.get('data')
                    ttl = answer.get('TTL', 60)

                    self.cache.set(domain, ip, ttl)

                    logger.info(f'DoH resolved: {domain} -> {ip} (TTL {ttl}s)')

                    return ip
        except Exception as e:
            logger.debug(f'DoH parse error: {e}')

        return

    async def resolve_batch(self, domains):
        tasks = [self.resolve(d) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            d: (r if not isinstance(r, Exception) else None)
            for d, r in zip(domains, results)
        }


class DnsInterceptor:
    def __init__(self, resolver, host='127.0.0.1', port=5353):
        self.resolver = resolver
        self.host = host
        self.port = port
        self._transport = None

    async def start(self):
        loop = asyncio.get_event_loop()

        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpDns(self.resolver),
            local_addr=(self.host, self.port)
        )

        logger.info(f'DNS interceptor listening on {self.host}:{self.port}/UDP')

    def stop(self):
        if self._transport:
            self._transport.close()


class _UdpDns(asyncio.DatagramProtocol):
    def __init__(self, resolver):
        self.resolver = resolver
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data, addr):
        try:
            domain, qtype, txid = _dns_parse_query(data)

            if not domain:
                return

            if qtype == 1:
                ip = await self.resolver.resolve(domain)

                if ip:
                    self.transport.sendto(_dns_build_response(txid, domain, ip), addr)
        except Exception as e:
            logger.debug(f'DNS handle error: {e}')


def _dns_parse_query(data):
    try:
        if len(data) < 12:
            return None, None, None

        txid = struct.unpack('>H', data[:2])[0]

        if struct.unpack('>H', data[4:6])[0] == 0:
            return None, None, None

        off = 12
        labels = []

        while off < len(data):
            n = data[off]

            if n == 0:
                off += 1

                break

            off += 1

            labels.append(data[off:off + n].decode('ascii', errors='ignore'))

            off += n

        domain = '.'.join(labels)
        qtype = struct.unpack('>H', data[off:off + 2])[0] if off + 2 <= len(data) else 1

        return domain, qtype, txid
    except Exception:
        return None, None, None

def _dns_build_response(txid, domain, ip):
    header = struct.pack('>HHHHHH', txid, 0x8180, 1, 1, 0, 0)
    qname = b''.join(bytes([len(p)]) + p.encode() for p in domain.split('.')) + b'\x00'
    question = qname + struct.pack('>HH', 1, 1)
    answer = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + bytes(map(int, ip.split('.')))

    return header + question + answer


def _is_ip(addr):
    try:
        ipaddress.ip_address(addr)

        return True
    except ValueError:
        return False


class Tunnel:
    def __init__(self, transport, config):
        self.t = transport
        self.crypto = Crypto()
        self.seq = Sequencer()
        self.auth = ConnectionAuth(config.get('pre_shared_key', 'changeme'))
        self.sni = random.choice(FAKE_SNI_LIST)
        self._cover = None
        self._ready = False

    async def connect(self):
        self.t.writer.write(build_tls_client_hello(self.sni))

        await self.t.writer.drain()

        logger.info(f'TLS ClientHello sent (SNI: {self.sni})')

        token = self.auth.generate_token()

        await self.t.send(tls_wrap(token))

        pkt = packet_encode(PacketType.HANDSHAKE, self.crypto.public_key_bytes, seq=0)

        await self.t.send(tls_wrap(pkt))

        raw = await self.t.recv()

        ptype, payload, _ = packet_decode(tls_unwrap(raw))

        if ptype != PacketType.HANDSHAKE:
            raise ValueError('Expected HANDSHAKE from server')

        self.crypto.perform_handshake(payload)

        self.t.crypto = self.crypto
        self._ready = True

        self._cover = CoverTraffic(self._send_cover)

        await self._cover.start()

        logger.info('Tunnel established')

    async def send_data(self, addr, port, payload):
        if not self._ready:
            raise RuntimeError('Tunnel not ready.')

        try:
            socket.inet_aton(addr)
            addr_bytes = b'\x01' + socket.inet_aton(addr)
        except OSError:
            enc = addr.encode()
            addr_bytes = b'\x03' + bytes([len(enc)]) + enc

        data = addr_bytes + struct.pack('>H', port) + payload
        pkt = packet_encode(PacketType.DATA, data, self.seq.next_seq())

        await jitter()

        await self.t.send(tls_wrap(self.crypto.encrypt(pkt)))

    async def recv_data(self):
        raw = await self.t.recv()

        ptype, payload, seq = packet_decode(self.crypto.decrypt(tls_unwrap(raw)))

        if not self.seq.valid(seq):
            logger.warning('Replay packet dropped')

            return

        if ptype == PacketType.DATA:
            return payload

        if ptype in (PacketType.KEEPALIVE, PacketType.COVER):
            return

        if ptype == PacketType.DISCONNECT:
            raise ConnectionError('Server sent DISCONNECT')

        return

    async def send_keepalive(self):
        pkt = packet_encode(PacketType.KEEPALIVE, b'', self.seq.next_seq(), add_padding=False)

        await self.t.send(tls_wrap(self.crypto.encrypt(pkt)))

    async def _send_cover(self, data):
        pkt = packet_encode(PacketType.COVER, data, self.seq.next_seq())

        await self.t.send(tls_wrap(self.crypto.encrypt(pkt)))

    async def close(self):
        if self._cover:
            await self._cover.stop()

        try:
            pkt = packet_encode(PacketType.DISCONNECT, b'', self.seq.next_seq(), add_padding=False)

            await self.t.send(tls_wrap(self.crypto.encrypt(pkt)))
        except Exception:
            pass

        await self.t.close()


SOCKS5_VER = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_IPV4 = 0x01
SOCKS5_DOMAIN = 0x03
SOCKS5_IPV6 = 0x04


class Socks5Handler:
    def __init__(self, reader, writer, tunnel, dns=None):
        self.reader = reader
        self.writer = writer
        self.tunnel = tunnel
        self.dns = dns

    async def handle(self):
        try:
            await self._negotiate()

            addr, port = await self._read_request()

            resolved = addr

            if self.dns and not _is_ip(addr):
                ip = await self.dns.resolve(addr)

                if ip:
                    logger.info(f'DoH: {addr} -> {ip}')

                    resolved = ip

                else:
                    logger.warning(f'DoH could not resolve {addr}, using as-is')

            logger.info(f'SOCKS5 CONNECT -> {addr}:{port}')

            self.writer.write(
                bytes([SOCKS5_VER, 0x00, 0x00, SOCKS5_IPV4]) +
                b'\x00\x00\x00\x00' +
                struct.pack('>H', port)
            )

            await self.writer.drain()
            await self._relay(resolved, port)
        except Exception as e:
            logger.error(f'SOCKS5 error: {e}')
        finally:
            self.writer.close()

    async def _negotiate(self):
        _, nmethods = struct.unpack('BB', await self.reader.readexactly(2))

        await self.reader.readexactly(nmethods)

        self.writer.write(bytes([SOCKS5_VER, SOCKS5_NO_AUTH]))

        await self.writer.drain()

    async def _read_request(self):
        _, cmd, _, atype = struct.unpack('BBBB', await self.reader.readexactly(4))

        if cmd != SOCKS5_CMD_CONNECT:
            raise ValueError(f'Unsupported SOCKS5 command: {cmd}')

        if atype == SOCKS5_IPV4:
            addr = socket.inet_ntoa(await self.reader.readexactly(4))

        elif atype == SOCKS5_DOMAIN:
            n = ord(await self.reader.readexactly(1))
            addr = (await self.reader.readexactly(n)).decode()

        elif atype == SOCKS5_IPV6:
            addr = socket.inet_ntop(socket.AF_INET6, await self.reader.readexactly(16))

        else:
            raise ValueError(f'Unknown SOCKS5 atype: {atype}')

        port = struct.unpack('>H', await self.reader.readexactly(2))[0]

        return addr, port

    async def _relay(self, addr, port):
        async def up():
            while True:
                data = await self.reader.read(8192)

                if not data:
                    break

                await self.tunnel.send_data(addr, port, data)

        async def down():
            while True:
                data = await self.tunnel.recv_data()

                if data:
                    self.writer.write(data)

                    await self.writer.drain()

        await asyncio.gather(up(), down())


class ShapeshifterClient:
    def __init__(self, config):
        self.cfg = config
        self.server_host = config['server']['host']
        self.server_port = config['server']['port']
        self.socks5_host = config['client'].get('socks5_host', '127.0.0.1')
        self.socks5_port = config['client'].get('socks5_port', 1080)
        self._tunnel = None
        self._dns = DoHResolver(server=config['client'].get('doh_server', 'cloudflare-dns.com'))
        self._dns_interceptor = DnsInterceptor(
            resolver=self._dns,
            host='127.0.0.1',
            port=config['client'].get('dns_port', 5353)
        )

    async def start(self):
        reader, writer = await self._connect_with_retry()
        transport = Transport(reader, writer)

        self._tunnel = Tunnel(transport, self.cfg)

        await self._tunnel.connect()

        await self._dns_interceptor.start()

        asyncio.ensure_future(self._keepalive_loop())

        server = await asyncio.start_server(
            self._handle_socks5, self.socks5_host, self.socks5_port
        )

        logger.info(
            f'SOCKS5 proxy ready at {self.socks5_host}:{self.socks5_port} '
            f'| DNS over HTTPS active (no DNS leaks)'
        )

        async with server:
            await server.serve_forever()

    async def _connect_with_retry(self, max_retries=10, base_delay=2.0):
        for attempt in range(max_retries):
            try:
                return await asyncio.open_connection(self.server_host, self.server_port)
            except (ConnectionRefusedError, OSError) as e:
                wait = base_delay * (2 ** min(attempt, 5))

                logger.warning(f'Attempt {attempt + 1} failed: {e}. Retry in {wait:.1f}s')

                await asyncio.sleep(wait)

        raise ConnectionError(f'Could not connect to {self.server_host}:{self.server_port}')

    async def _handle_socks5(self, reader, writer):
        handler = Socks5Handler(reader, writer, self._tunnel, dns=self._dns)

        await handler.handle()

    async def _keepalive_loop(self, interval=30.0):
        while True:
            await asyncio.sleep(interval)

            try:
                await self._tunnel.send_keepalive()
            except Exception:
                break


async def main():
    with open('config.json') as f:
        config = json.load(f)

    await ShapeshifterClient(config).start()


if __name__ == '__main__':
    asyncio.run(main())
