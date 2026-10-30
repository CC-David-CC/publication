"""Fail-closed, loopback-only lookup of operator-offered official channels."""
import asyncio
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import quote, urlsplit

class OfficialChannelChecker:
    def __init__(self, port, issuer):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Explicit local official-reader port required')
        origin=urlsplit(issuer)
        if origin.scheme!='https' or not origin.netloc or origin.username or origin.password or origin.path not in ('','/') or origin.query or origin.fragment:
            raise ValueError('Exact HTTPS issuer origin required')
        self.port = port
        self.host = origin.netloc
        self.slots = asyncio.Semaphore(8)

    def _read(self, channel, genesis):
        url = f'http://127.0.0.1:{self.port}/official-channel?channel={quote(channel, safe="")}'
        try:
            with urlopen(Request(url, headers={'Accept': 'application/json', 'Host': self.host}), timeout=1) as response:
                if response.status != 200:
                    return False
                raw = response.read(65537)
            if len(raw) > 65536:
                return False
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) != {'items', 'next'} or data['next'] is not None or not isinstance(data['items'], list) or len(data['items']) != 1:
                return False
            item = data['items'][0]
            return isinstance(item, dict) and item.get('category') == 'official' and item.get('channel') == channel and item.get('genesisHash') == genesis
        except (HTTPError, URLError, OSError, ValueError, TimeoutError):
            return False

    async def __call__(self, channel, genesis):
        async with self.slots:
            return await asyncio.to_thread(self._read, channel, genesis)
