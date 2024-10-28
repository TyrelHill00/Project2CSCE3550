from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time
from cryptography.hazmat.backends import default_backend

# Constants
hostName = "localhost"
serverPort = 8080
DB_FILE = 'totally_not_my_privateKeys.db'


# Database initialization
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys (
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL
                      )''')
    conn.commit()
    return conn


def store_key(key, exp):
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key, exp))
    conn.commit()
    conn.close()


# Generate and store keys (both expired and valid)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    expired_time = int(time.time()) - 3600
    store_key(pem, expired_time)

    valid_time = int(time.time()) + 3600
    store_key(pem, valid_time)


# Retrieve a private key from the database
def get_private_key(expired=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if expired:
        cursor.execute('SELECT key FROM keys WHERE exp <= ?', (int(time.time()),))
    else:
        cursor.execute('SELECT key FROM keys WHERE exp > ?', (int(time.time()),))

    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0]
    else:
        raise Exception("No suitable key found")


# JWT signing using retrieved private key
def sign_jwt(expired=False):
    private_key_pem = get_private_key(expired)
    
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    payload = {
        "some": "payload",
        "exp": int(time.time()) + 600  # JWT expires in 10 minutes
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return token


# JWKS retrieval
def get_all_valid_keys():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT key FROM keys WHERE exp > ?', (int(time.time()),))
    results = cursor.fetchall()
    conn.close()

    public_keys = []
    for key in results:
        private_key = serialization.load_pem_private_key(
            key[0],
            password=None,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_keys.append(public_key)

    return public_keys


# JWKS response construction
def jwks_response():
    valid_keys = get_all_valid_keys()
    jwks = {"keys": []}
    
    for pub_key in valid_keys:
        public_key_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Here you can populate the JWKS key fields based on public_key_pem
        jwks["keys"].append({"key": public_key_pem.decode("utf-8")})

    return jwks


# Integer to Base64 conversion
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


# HTTP server implementation
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            try:
                expired = 'expired' in params
                encoded_jwt = sign_jwt(expired)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes(str(e), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            try:
                keys = jwks_response()
                self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes(str(e), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    # Generate and store keys when starting the server
    generate_keys()

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
