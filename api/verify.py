import json
import jwt
from jwt import InvalidTokenError
from http.server import BaseHTTPRequestHandler

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-v0wsq391.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

class handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request_data = json.loads(self.rfile.read(length).decode("utf-8"))
            token = request_data.get("token")

            if not isinstance(token, str) or not token:
                self.send_json(401, {"valid": False})
                return

            claims = jwt.decode(
                token,
                PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=ISSUER,
                audience=AUDIENCE,
                options={"require": ["exp", "iss", "aud", "sub"]}
            )

            self.send_json(200, {
                "valid": True,
                "email": claims.get("email"),
                "sub": claims.get("sub"),
                "aud": claims.get("aud")
            })

        except (InvalidTokenError, ValueError, json.JSONDecodeError):
            self.send_json(401, {"valid": False})
        except Exception:
            self.send_json(401, {"valid": False})
