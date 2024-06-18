import argparse
import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import random
import time
import tomllib
from typing import Any
from httpx import AsyncClient

MAX_INT = pow(2, 31)


def random_string(length: str) -> str:
    characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join((random.choice(characters) for _ in range(length)))


@dataclass
class ServerConfig:

    api_url: str
    username: str
    password: str
    origin: str = None
    referer: str = None


class PokeClient:

    HEADERS = {
        "accept": "application/x-www-form-urlencoded",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/x-www-form-urlencoded",
        "priority": "u=1, i",
        "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    }

    def __init__(self, api_url: str, username: str, password: str, origin: str = '', referer: str = '') -> None:
        self.headers = {
            **self.HEADERS
        }
        if origin != '':
            self.headers['origin'] = origin
        if referer != '':
            self.headers['referer'] = referer
        self.client = AsyncClient(
            headers=self.headers,
            base_url=api_url
        )
        self._username = username
        self._password = password

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        await self.login(self._username, self._password)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    async def login(self, username: str, password: str) -> str | None:
        endpoint = '/account/login'
        post_data = {'username': username, 'password': password}
        await self.client.options(endpoint)
        resp = await self.client.post(endpoint, data=post_data)
        token = resp.json().get('token')
        if token is not None:
            self.client.headers['Authorization'] = token
        return token

    async def info(self):
        endpoint = '/account/info'
        resp = await self.client.get(endpoint)
        return resp.json()

    async def system(self, client_session_id: str):
        endpoint = '/savedata/system'
        params = {'clientSessionId': client_session_id}
        await self.client.options(endpoint, params=params)
        resp = await self.client.get(endpoint, params=params)
        return resp.json()

    async def update(self, data: dict, datatype: int, client_session_id: str) -> bool:
        endpoint = '/savedata/update'
        params = {
            'datatype': datatype,
            'trainerId': data['trainerId'],
            'secretId': data['secretId'],
            'clientSessionId': client_session_id
        }
        await self.client.options(endpoint, params=params)
        # cls=BigIntConverter))
        resp = await self.client.post(endpoint, params=params, data=json.dumps(data,))
        return resp.status_code == 200


async def replay(from_config: ServerConfig = None, to_config: ServerConfig = None,  dump_json: Path = None, load_json: Path = None, eggs: int = 0) -> bool:
    session_id = random_string(32)
    if load_json is None:
        async with PokeClient(
            api_url=from_config.api_url, username=from_config.username,
            password=from_config.password, origin=from_config.origin, referer=from_config.referer
        ) as from_server:
            from_server_data = await from_server.system(session_id)
            if dump_json is not None:
                with open(dump_json, 'w') as f:
                    json.dump(from_server_data, f)
                    return True
    else:
        with open(load_json, 'r') as f:
            from_server_data = json.load(f)
    async with PokeClient(
            api_url=to_config.api_url, username=to_config.username,
            password=to_config.password, origin=to_config.origin, referer=to_config.referer
    ) as to_server:
        to_server_data = await to_server.system(session_id)
        if eggs != 0:
            from_server_data['voucherCounts'] = {
                k: v+eggs for k, v in from_server_data['voucherCounts'].items()}
        from_server_data['trainerId'] = to_server_data['trainerId']
        from_server_data['secretId'] = to_server_data['secretId']
        from_server_data['timestamp'] = int(time.time() * 1000)
        return await to_server.update(from_server_data, 0, session_id)


async def main():
    parser = argparse.ArgumentParser(prog='replay.py')
    parser.add_argument(
        '-c', '--config', help='configure file', default='config.toml')
    parser.add_argument('-d', '--dump', help='dump data json')
    parser.add_argument('-l', '--load', help='load data json')
    parser.add_argument(
        '-e', '--eggs', help='add more voucherCounts', type=int, default=0)

    args = parser.parse_args()

    config_file = Path(args.config)
    if not config_file.exists():
        print('configure file not found, exit')
        return
    with open(config_file, 'rb') as f:
        config = tomllib.load(f)

    to_config = ServerConfig(**config['to_server'])
    from_config = ServerConfig(**config['from_server'])
    dump_json = None if args.dump is None else Path(args.dump)
    load_json = None if args.load is None else Path(args.load)
    eggs = args.eggs

    if dump_json is not None:
        print(f"Dump [{from_config.username}]({from_config.api_url}) as [{dump_json}]")
    else:
        if load_json is None:
            print(f"Copy [{from_config.username}]({from_config.api_url}) => [{
                to_config.username}]({to_config.api_url})")
        else:
            print(f"Copy [{load_json}] => [{
                to_config.username}]({to_config.api_url})")        

    result = await replay(from_config=from_config, to_config=to_config, dump_json=dump_json, load_json=load_json, eggs=eggs)

    print(f"Status: {'Finished' if result else 'Failed'}")

if __name__ == '__main__':
    asyncio.run(main())
