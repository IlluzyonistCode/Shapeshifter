import asyncio
import socket
import struct
import hashlib
import hmac
import json
import os
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
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('shapeshifter.server')

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


class ClientSession:
    def __init__(self, transport, config):
        self.t = transport
        self.crypto = Crypto()
        self.seq = Sequencer()
        self.auth = ConnectionAuth(config.get('pre_shared_key', 'changeme'))
        self.sni = random.choice(FAKE_SNI_LIST)
        self._cover = None

    async def run(self):
        peer = self.t.peer
        logger.info(f'New connection: {peer[0]}:{peer[1]}')

        try:
            if not await self._authenticate():
                logger.warning(f'Rejected unauthenticated connection from {peer[0]}:{peer[1]}')

                return

            await self._handshake()

            self._cover = CoverTraffic(self._send_cover)

            await self._cover.start()
            await self._proxy_loop()
        except asyncio.IncompleteReadError:
            logger.info(f'Client {peer[0]}:{peer[1]} disconnected')
        except Exception as e:
            logger.error(f'Session error {peer}: {e}')
        finally:
            if self._cover:
                await self._cover.stop()

            await self.t.close()

    async def _authenticate(self):
        try:
            raw = await asyncio.wait_for(self.t.recv(), timeout=10.0)

            token = tls_unwrap(raw)

            return self.auth.verify_token(token)
        except Exception:
            return False

    async def _handshake(self):
        pkt = packet_encode(PacketType.HANDSHAKE, self.crypto.public_key_bytes, seq=0)

        await self.t.send(tls_wrap(pkt))

        raw = await self.t.recv()
        _, payload, _ = packet_decode(tls_unwrap(raw))

        if _ != PacketType.HANDSHAKE:
            raise ValueError('Expected HANDSHAKE packet')

        self.crypto.perform_handshake(payload)
        self.t.crypto = self.crypto

        logger.info(f'Handshake complete with {self.t.peer}')

    async def _proxy_loop(self):
        while True:
            raw = await self.t.recv()

            ptype, payload, seq = packet_decode(self.crypto.decrypt(tls_unwrap(raw)))

            if not self.seq.valid(seq):
                logger.warning('Replay packet dropped')

                continue

            if ptype == PacketType.COVER:
                continue

            if ptype == PacketType.KEEPALIVE:
                await self._send_ack(seq)

                continue

            if ptype == PacketType.DISCONNECT:
                logger.info(f'Client {self.t.peer} sent DISCONNECT')

                break

            if ptype == PacketType.DATA:
                response = await self._forward(payload)

                if response:
                    await self._send_data(response)

    async def _forward(self, data):
        if len(data) < 4:
            return

        atype = data[0]
        off = 1

        if atype == 0x01:
            addr = socket.inet_ntoa(data[off:off + 4])
            off += 4

        elif atype == 0x03:
            dlen = data[off]; off += 1
            addr = data[off:off + dlen].decode(); off += dlen

        elif atype == 0x04:
            addr = socket.inet_ntop(socket.AF_INET6, data[off:off + 16]); off += 16

        else:
            logger.warning(f'Unknown addr type: {atype}')

            return

        port = struct.unpack('>H', data[off:off + 2])[0]
        payload = data[off + 2:]

        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(addr, port), timeout=10.0)

            w.write(payload)

            await w.drain()

            response = await asyncio.wait_for(r.read(65536), timeout=10.0)

            w.close()

            return response
        except Exception as e:
            logger.error(f'Upstream {addr}:{port} failed: {e}')

            return
    async def _send_data(self, data):
        pkt = packet_encode(PacketType.DATA, data, self.seq.next_seq())

        await self.t.send(tls_wrap(self.crypto.encrypt(pkt)))

    async def _send_ack(self, acked_seq):
        pkt = packet_encode(PacketType.ACK, struct.pack('>I', acked_seq), self.seq.next_seq(), add_padding=False)

        await self.t.send(tls_wrap(self.crypto.encrypt(pkt)))

    async def _send_cover(self, data):
        pkt = packet_encode(PacketType.COVER, data, self.seq.next_seq())

        await self.t.send(tls_wrap(self.crypto.encrypt(pkt)))


class ShapeshifterServer:
    def __init__(self, config):
        self.config = config
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 8443)

    async def start(self):
        server = await asyncio.start_server(self._handle, self.host, self.port)
        logger.info(f'Shapeshifter server listening on {self.host}:{self.port}')

        async with server:
            await server.serve_forever()

    async def _handle(self, reader, writer):
        t = Transport(reader, writer)
        session = ClientSession(t, self.config)

        await session.run()


async def main():
    with open('config.json') as f:
        config = json.load(f)

    await ShapeshifterServer(config['server']).start()


if __name__ == '__main__':
    asyncio.run(main())
