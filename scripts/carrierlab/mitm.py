#!/usr/bin/env python3
"""A TLS-inspecting proxy, as some company and school networks run one: it
ends a client's TLS with a certificate of its own, opens TLS of its own to
where the client was going, and passes along what is inside — able to read
all of it. Nothing here knows SHARP-256: it is Python's ssl module, which is
OpenSSL, on both sides.

    mitm.py LISTEN_PORT UPSTREAM_HOST UPSTREAM_PORT CERT KEY
"""

import asyncio
import ssl
import sys


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            writer.close()
        except (OSError, ssl.SSLError):
            pass


async def main():
    port, up_host, up_port, cert, key = sys.argv[1:6]
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE

    async def handle(c_reader, c_writer):
        peer = c_writer.get_extra_info("peername")
        try:
            u_reader, u_writer = await asyncio.wait_for(
                asyncio.open_connection(up_host, int(up_port), ssl=client, server_hostname=""), 5
            )
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
            print(f"{peer}: upstream failed: {e}", flush=True)
            c_writer.close()
            return
        print(f"{peer}: opened, and passed on to {up_host}:{up_port}", flush=True)
        await asyncio.gather(pipe(c_reader, u_writer), pipe(u_reader, c_writer))

    srv = await asyncio.start_server(handle, host=None, port=int(port), ssl=server)
    print(f"inspecting TLS on port {port}", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
