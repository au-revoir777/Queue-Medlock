import random
import string
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import requests

AUTH_URL = "http://localhost:8001"
TENANT_URL = "http://localhost:8002"
KMS_URL = "http://localhost:8003"
BROKER_URL = "http://localhost:9000"

MAX_WORKERS = 100


def random_id(prefix="id"):
    return (
        prefix
        + "_"
        + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    )


class Environment:
    def __init__(self):
        self.hospitals = {}

    def create_hospital(self):
        hospital_id = random_id("hospital")
        requests.post(
            f"{TENANT_URL}/hospitals", json={"id": hospital_id, "name": hospital_id}
        )
        self.hospitals[hospital_id] = {}
        print(f"[+] Created hospital {hospital_id}")
        return hospital_id

    def create_department(self, hospital_id):
        department_id = random_id("dept")
        requests.post(
            f"{TENANT_URL}/hospitals/{hospital_id}/departments",
            json={"id": department_id, "name": department_id},
        )
        self.hospitals[hospital_id][department_id] = []
        print(f"[+] Created department {department_id}")
        return department_id

    def register_staff(self, hospital_id, department_id):
        staff_id = random_id("staff")
        requests.post(
            f"{TENANT_URL}/staff/register",
            json={
                "id": staff_id,
                "hospital_id": hospital_id,
                "role": random.choice(["doctor", "nurse", "admin"]),
                "public_sign_key": random_id("sign"),
                "public_kx_key": random_id("kx"),
            },
        )
        self.hospitals[hospital_id][department_id].append(staff_id)
        print(f"[+] Registered staff {staff_id}")
        return staff_id


env = Environment()


def login(staff_id, hospital_id):
    r = requests.post(
        f"{AUTH_URL}/login",
        json={
            "hospital_id": hospital_id,
            "staff_id": staff_id,
            "password": "password123",
        },
    )
    if r.status_code == 200:
        return r.json()
    return None


def send_message(token, hospital_id, department_id, sender_id):
    payload = {
        "hospital_id": hospital_id,
        "department_id": department_id,
        "sender_id": sender_id,
        "ciphertext": random_id("cipher"),
        "signature": random_id("sig"),
    }

    requests.post(
        f"{BROKER_URL}/enqueue",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


def poll_messages(token, hospital_id, department_id):
    requests.get(
        f"{BROKER_URL}/dequeue/{hospital_id}/{department_id}",
        headers={"Authorization": f"Bearer {token}"},
    )


def staff_lifecycle(hospital_id, department_id, staff_id):
    tokens = login(staff_id, hospital_id)
    if not tokens:
        return

    access = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    while True:
        action = random.random()

        if action < 0.6:
            send_message(access, hospital_id, department_id, staff_id)
        elif action < 0.9:
            poll_messages(access, hospital_id, department_id)
        else:
            # Occasionally refresh token
            r = requests.post(
                f"{AUTH_URL}/refresh", json={"refresh_token": refresh_token}
            )
            if r.status_code == 200:
                tokens = r.json()
                access = tokens["access_token"]
                refresh_token = tokens["refresh_token"]

        time.sleep(random.uniform(0.3, 1.5))


def dynamic_growth():
    while True:
        time.sleep(random.uniform(10, 20))

        hospital_id = env.create_hospital()

        for _ in range(random.randint(1, 3)):
            dept_id = env.create_department(hospital_id)

            for _ in range(random.randint(3, 8)):
                staff_id = env.register_staff(hospital_id, dept_id)
                executor.submit(staff_lifecycle, hospital_id, dept_id, staff_id)


def simulate():
    print("🚀 Starting continuous zero-trust simulation")

    # Initial bootstrap
    for _ in range(2):
        hospital_id = env.create_hospital()
        for _ in range(2):
            dept_id = env.create_department(hospital_id)
            for _ in range(5):
                staff_id = env.register_staff(hospital_id, dept_id)
                executor.submit(staff_lifecycle, hospital_id, dept_id, staff_id)

    # Dynamic tenant growth thread
    threading.Thread(target=dynamic_growth, daemon=True).start()

    while True:
        time.sleep(5)


if __name__ == "__main__":
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    simulate()
