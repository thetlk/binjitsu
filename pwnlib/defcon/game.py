"""Describes a way to submit a key to a key server.
"""
import os

from ..tubes.remote import remote
from ..context import context

env_server  = os.getenv('FLAG_HOST', 'flag-submission-server')
env_port    = os.getenv('FLAG_PORT', 1337)
env_proto   = os.getenv('FLAG_PROTO', 'tcp')
env_exploit_name = os.getenv('EXPLOIT_NAME', 'unnamed-exploit')
env_target_host  = os.getenv('TARGET_HOST', 'unknown-target')

def submit_flag(flag,
                exploit=env_exploit_name,
                target=env_target_host,
                server=env_server,
                port=env_port, proto=env_proto):
    """
    Submits a flag to the game server

    Arguments:
        flag(str): The flag to submit.
        exploit(str): Exploit identifier, optional
        target(str): Target identifier, optional
        server(str): Flag server host name, optional
        port(int): Flag server port, optional
        proto(str), Flag server protocol, optional

    Optional arguments are inferred from the environment,
    or omitted if none is set.

    Returns:
        A string indicating the status of the key submission,
        or an error code.
    """
    with remote(server, port) as r:
        r.sendline(flag)
        r.sendline(exploit or env_exploit_name)
        r.sendline(target or env_target_host)
        return r.recvall()