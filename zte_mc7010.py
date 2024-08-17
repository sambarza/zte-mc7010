import asyncio
import aiohttp

from hashlib import sha256, md5
from time import time

import json

from dataclasses import dataclass
from http import cookies


@dataclass
class ZteResponse:
    payload: str
    cookies: cookies.SimpleCookie


#  ------------------ GENERIC FUNCTIONS --------------------
def current_epoch() -> str:
    # EPOCH now in milliseconds
    return str(round(time() * 1000))


def zte_sha256(text: str) -> str:
    return sha256(text.encode()).hexdigest().upper()


def hex_md5(text: str) -> str:
    return md5(text.encode()).hexdigest()


def encode_password(password, ld):
    password_hash = zte_sha256(password)

    return zte_sha256(password_hash + ld)


def calculate_ad(wa_inner_version, cr_version, RD):

    return hex_md5(hex_md5(wa_inner_version + cr_version) + RD)


#  ------------------ HTTP REQUEST --------------------
async def get_cmd_process(host, login_token, cmd) -> ZteResponse:

    async with aiohttp.ClientSession(cookies={"stok": login_token}) as session:
        async with session.get(
            url=f"http://{host}/goform/goform_get_cmd_process?isTest=false&cmd={cmd}&multi_data=1&_={current_epoch()}",
            headers={"Referer": f"http://{host}/"},
        ) as response:

            return ZteResponse(
                await response.json(content_type="text/html"), response.cookies
            )


async def set_cmd_process(host, login_token, goformId, data):

    async with aiohttp.ClientSession() as session:

        async with session.post(
            url=f"http://{host}/goform/goform_set_cmd_process",
            headers={
                "Referer": f"http://{host}/",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            },
            data=f"isTest=false&goformId={goformId}&{data}",
            cookies={"stok": login_token},
        ) as response:

            return ZteResponse(
                await response.json(content_type="text/html"), response.cookies
            )


#  ----------------------------------------------------
async def get_ld(host) -> str:
    response = await get_cmd_process(host, "", "LD")

    return response.payload["LD"]


async def get_login_token(host: str, encoded_password: str) -> bool:

    response = await set_cmd_process(host, "", "LOGIN", f"password={encoded_password}")

    return response.cookies["stok"].value


#  --------------------- PUBLIC APIs --------------------------
async def login(host, password: str) -> str:

    ld = await get_ld(host)

    encoded_password = encode_password(password, ld)

    login_token = await get_login_token(host=host, encoded_password=encoded_password)

    return login_token


async def get_active_band(host, login_token):

    response = await get_cmd_process(
        host=host, login_token=login_token, cmd="wan_active_band"
    )

    return response.payload["wan_active_band"]


async def speed_up(host, login_token):

    response = await get_cmd_process(
        host, login_token, cmd="wa_inner_version,cr_version,RD"
    )

    ad = calculate_ad(
        response.payload["wa_inner_version"],
        response.payload["cr_version"],
        response.payload["RD"],
    )

    response = await set_cmd_process(
        host,
        login_token,
        "WAN_PERFORM_NR5G_BAND_LOCK",
        f"nr5g_band_mask=20%2C1%2C3&AD={ad}",
    )

    print(response.payload)

    return response.payload


# ---------------- M A I N ---------------
async def main():

    with open("config.json") as f:
        config = json.load(f)

    host = config["host"]
    password = config["password"]

    login_token = await login(host, password)
    active_band = await get_active_band(host, login_token)
    await speed_up(host, login_token)

    print(active_band)


if __name__ == "__main__":
    asyncio.run(main())
