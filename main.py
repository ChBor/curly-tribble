import random
import base64
import hashlib

a = []

class PasswordHandler:

    def hash_password_raw(self, password: str) -> str:
        hash_data = hashlib.sha256(password.encode("utf-8"))
        return base64.b64encode(hash_data.digest()).decode("utf-8")

    def hash_password(self, password: str, pepper="") -> str:
        salt_number = random.randint(0, 2 ** 256 - 1)
        salt = base64.b64encode(salt_number.to_bytes(32, "little")).decode("utf-8")
        a.append(self.hash_password_raw(password + ":" + salt + ":" + pepper) + ":" + salt + ":" + pepper)
        return a[0]

    def verify_password(self, password: str, hash: str) -> bool:
        raw_hash, salt, pepper = hash.split(":", 3)
        return self.hash_password_raw(password + ":" + salt + ":" + pepper) == raw_hash


user = PasswordHandler()
print(user.verify_password("password", user.hash_password("password")))
