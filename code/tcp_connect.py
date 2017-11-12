"""
    REFERENCES: 
    1. https://www.blog.pythonlibrary.org/2016/07/26/python-3-an-intro-to-asyncio/
    2. https://github.com/python/asyncio/blob/master/examples/simple_tcp_server.py
    3. https://hackernoon.com/asyncio-for-the-working-python-developer-5c468e6e2e8e
    4. http://asyncio.readthedocs.io/en/latest/hello_world.html

    Example of a simple TCP server that is written in (mostly) coroutine
    style and uses asyncio.streams.start_server() and
    asyncio.streams.open_connection().
    Note that running this example starts both the TCP server and client
    in the same process.  It listens on port 7201 on 127.0.0.1, so it will
    fail if this port is currently in use.
"""

import sys
import asyncio
import asyncio.streams
import struct


class NSEServer:
    """
        This is just an example of how a TCP server might be potentially
        structured.  This class has basically 3 methods: start the server,
        handle a client, and stop the server.
    """
    def __init__(self):
        self.server = None 
        self.clients = {} 


    """
        This method accepts a new client connection and creates a Task
        to handle this client.  self.clients is updated to keep track
        of the new client.
    """
    def _accept_client(self, client_reader, client_writer):
        task = asyncio.Task(self._handle_client(client_reader, client_writer))
        self.clients[task] = (client_reader, client_writer)

        def client_done(task):
            print("client task done:", task, file=sys.stderr)
            del self.clients[task]

        task.add_done_callback(client_done)


    """
        This method actually does the work to handle the requests for
        a specific client.  The protocol is line oriented, so there is
        a main loop that reads a line with a request and then sends
        out one or more lines back to the client with the result.
    """
    def _handle_client(self, client_reader, client_writer):
        while True:
            try:
                data = (yield from client_reader.read(4))
            except IOError as io_error:
                print("IO Error! Closing connection now!")
                print(io_error)
            
            if not data: 
                client_writer.close()

            packed = struct.pack('!2H2I', 12, 521, 0, 2)
            try:
                client_writer.write(packed)
            except:
                print("Client response failed, closing connection!")
                return


    """
        Starts the TCP server, so that it listens on port 7002.
        For each client that connects, the accept_client method gets
        called.  This method runs the loop until the server sockets
        are ready to accept connections.
    """
    def start(self, loop):
        self.server = loop.run_until_complete(
            asyncio.streams.start_server(self._accept_client,'127.0.0.1', '7002', loop=loop))


    """
        Stops the TCP server, i.e. closes the listening socket(s).
        This method runs the loop until the server sockets are closed.
    """
    def stop(self, loop):
        if self.server is not None:
            self.server.close()
            loop.run_until_complete(self.server.wait_closed())
            self.server = None

"""
    Cleans up all tasks
"""
def cleanup(loop):
    tasks = asyncio.Task.all_tasks(loop)
    for t in tasks:
        t.cancel()
    loop.run_until_complete(asyncio.sleep(0))


if __name__ == "__main__":
    print("This module connects to the server")