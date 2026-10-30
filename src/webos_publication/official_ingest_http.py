"""Experimental local ingest for an explicitly authorized official replica.

Loopback only; this is not a browser endpoint or a production deployment.
Only replayed, signature-checked history is promoted from bounded scratch.
"""
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .official_content import _id
from .official_registry import OfficialChannelRegistry


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


class OfficialIngestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, database, token):
        if not isinstance(token, str) or len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
            raise ValueError('A 256-bit lowercase hex token is required')
        self.database = database
        self.token = token
        self.slots = threading.BoundedSemaphore(2)
        super().__init__(('127.0.0.1', 0), OfficialIngestHandler)


class OfficialIngestHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, value):
        data = json.dumps(value, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.close_connection = True
        supplied = self.headers.get('Authorization', '')
        if not supplied.isascii() or not hmac.compare_digest(supplied, 'Bearer ' + self.server.token):
            return self.reply(403, {'error': 'forbidden'})
        if self.path not in ('/official-ingest','/official-ingest-authorized') or self.headers.get('Origin') or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type') != 'application/json':
            return self.reply(400, {'error': 'invalid request'})
        length = self.headers.get('Content-Length', '')
        if not length.isascii() or not length.isdecimal() or len(length) > 8 or not 1 <= int(length) <= (9 if self.path.endswith('-authorized') else 8) * 1048576:
            return self.reply(400, {'error': 'invalid request'})
        if not self.server.slots.acquire(blocking=False):
            return self.reply(503, {'error': 'busy'})
        try:
            self.connection.settimeout(15)
            raw = self.rfile.read(int(length))
            if len(raw) != int(length):
                raise ValueError('incomplete request')
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid number')))
            uploader=None
            if self.path.endswith('-authorized'):
                if not isinstance(value,dict) or set(value)!={'offer','uploader'} or not isinstance(value['offer'],str) or len(value['offer'].encode())>8*1048576:raise ValueError('invalid envelope')
                uploader=value['uploader'];value=json.loads(value['offer'],object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid number')))
            if not isinstance(value, dict) or set(value) != {'channel', 'expectedHead', 'nodes', 'history', 'height', 'head'}:
                raise ValueError('invalid payload')
            for key in ('channel', 'expectedHead', 'history', 'head'):
                _id(value[key])
            if type(value['height']) is not int or value['height'] < 1 or not isinstance(value['nodes'], list) or not 1 <= len(value['nodes']) <= 4096:
                raise ValueError('invalid payload')
            nodes = value['nodes']
            if any(not isinstance(node, dict) or set(node) != {'cid', 'wire'} or not isinstance(node['wire'], str) for node in nodes):
                raise ValueError('invalid node')
            registry = OfficialChannelRegistry(self.server.database)
            try:
                for node in nodes:
                    registry.stage_node(value['channel'], node['cid'], node['wire'])
                result = registry.append_staged_history(value['channel'], expected_head=value['expectedHead'], history=value['history'], height=value['height'], head=value['head'],uploader=uploader)
                return self.reply(200, {'height': result['height'], 'head': result['head']})
            finally:
                registry.close()
        except (ValueError, KeyError, UnicodeError, json.JSONDecodeError):
            return self.reply(409, {'error': 'history rejected'})
        finally:
            self.server.slots.release()
