import http.server
import socketserver
from sys import argv
from time import sleep


if len(argv) < 3:
    print("Error missing arguments")
    exit(1)

PORT = int(argv[1])
SLEEP = int(argv[2])

class SlowHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        sleep(SLEEP)
        return super().do_GET()

Handler = SlowHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port %d ; wait=%d sec" % (PORT, SLEEP) )
    httpd.serve_forever()
