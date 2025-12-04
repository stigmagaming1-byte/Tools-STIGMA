from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os

# Import handlers
from api.auth import handler as AuthHandler
from api.check import handler as CheckHandler

class MainHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/api/auth/'):
            # Route to auth handler
            auth_handler = AuthHandler(self.request, (self.client_address[0], self.client_address[1]), self.server)
            auth_handler.path = self.path
            auth_handler.headers = self.headers
            auth_handler.do_GET()
        elif self.path.startswith('/api/check'):
            # Route to check handler
            check_handler = CheckHandler(self.request, (self.client_address[0], self.client_address[1]), self.server)
            check_handler.path = self.path
            check_handler.headers = self.headers
            check_handler.do_GET()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith('/api/auth/'):
            # Route to auth handler
            auth_handler = AuthHandler(self.request, (self.client_address[0], self.client_address[1]), self.server)
            auth_handler.path = self.path
            auth_handler.headers = self.headers
            auth_handler.do_POST()
        elif self.path.startswith('/api/check'):
            # Route to check handler
            check_handler = CheckHandler(self.request, (self.client_address[0], self.client_address[1]), self.server)
            check_handler.path = self.path
            check_handler.headers = self.headers
            check_handler.do_POST()
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if self.path.startswith('/api/auth/'):
            # Route to auth handler
            auth_handler = AuthHandler(self.request, (self.client_address[0], self.client_address[1]), self.server)
            auth_handler.path = self.path
            auth_handler.headers = self.headers
            auth_handler.do_DELETE()
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MainHandler)
    print(f'Server running on port {port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
