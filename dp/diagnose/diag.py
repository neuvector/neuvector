#!/usr/bin/python

import json
import os
import pprint
import socket
import sys

import click

RECV_BUFFER_SIZE = 8192
SERVER_SOCKET = "/tmp/dp_ctrl.sock"
CLIENT_SOCKET = "/tmp/dp_ctrl_client.%d"

class CtxData(object):
    def __init__(self):
        self.local_path = CLIENT_SOCKET % os.getpid()

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(self.local_path)
        try:
            sock.connect(SERVER_SOCKET)
        except socket.error, msg:
            click.echo("Unable to connect to dp_ctrl socket: %s" % msg)
            sys.exit(1)

        self.sock = sock

    def __del__(self):
        self.sock.close()
        os.remove(self.local_path)

@click.group()
@click.pass_context
def cli(ctx):
    ctx.obj = CtxData()

# -- session

@cli.group()
@click.pass_obj
def session(data):
    """Session operation."""

@session.command()
@click.pass_obj
def list(data):
    body = {"ctrl_list_session": dict()}
    data.sock.sendall(json.dumps(body))

    while True:
        resp = json.loads(data.sock.recv(RECV_BUFFER_SIZE))
        pprint.pprint(resp["sessions"])
        if not resp["more"]:
            break

@session.command()
@click.pass_obj
def count(data):
    body = {"ctrl_count_session": dict()}
    data.sock.sendall(json.dumps(body))

    resp = json.loads(data.sock.recv(RECV_BUFFER_SIZE))
    click.echo(resp["dp_count_session"])

# -- debug

@cli.group()
@click.pass_obj
def debug(data):
    """Debug operation."""

@debug.command()
@click.argument('cat', type=click.Choice(['all', 'init', 'error', 'ctrl', 'packet',
                                          'session', 'timer', 'tcp', 'parser']))
@click.pass_obj
def enable(data, cat):
    """Enable debug category."""
    body = {"ctrl_set_debug": {"categories": ["+%s" % cat]}}
    data.sock.sendall(json.dumps(body))

@debug.command()
@click.argument('cat', type=click.Choice(['all', 'init', 'error', 'ctrl', 'packet',
                                          'session', 'timer', 'tcp', 'parser']))
@click.pass_obj
def disable(data, cat):
    """Disable debug category."""
    body = {"ctrl_set_debug": {"categories": ["-%s" % cat]}}
    data.sock.sendall(json.dumps(body))

@debug.command()
@click.pass_obj
def show(data):
    """Show debug setting."""
    body = {"ctrl_get_debug": dict()}
    data.sock.sendall(json.dumps(body))

    resp = json.loads(data.sock.recv(RECV_BUFFER_SIZE))
    pprint.pprint(resp["dp_debug"])

# -- done


if __name__ == '__main__':
    cli()
