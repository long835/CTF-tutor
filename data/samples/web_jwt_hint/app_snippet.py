# Local study only — intentional weak JWT handling
import jwt

def verify(token):
    # BAD: does not enforce algorithm allow-list
    return jwt.decode(token, options={"verify_signature": False})
