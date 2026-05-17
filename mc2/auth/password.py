"""
Password hashing utilities using bcrypt directly.

passlib's bcrypt backend has a version-detection bug with bcrypt>=4.x
(AttributeError on __about__.__version__). Using bcrypt directly avoids
the issue while keeping the same $2b$ hash format.
"""

import bcrypt


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False
