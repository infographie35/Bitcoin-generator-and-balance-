import asyncio
import subprocess
import os
import time
import socket
import datetime
import json
from collections import deque
import binascii
import base58
import hashlib
import ecdsa

# File paths
positive_balance_csv = r'C:\Users\[YOUR_PATH]\wallets_with_positive_balance.csv'
electrum_path = r'C:\Users\[YOUR_PATH]\electrum-4.5.5-portable.exe'
# Number of wallets to generate --> EDIT line 227


# -------------------------------
# Time Estimator for progress
# -------------------------------
class TimeEstimator:
    def __init__(self, max_samples=200):
        self.times = deque(maxlen=max_samples)
        self.start_time = time.time()

    def update(self, elapsed_time):
        self.times.append(elapsed_time)

    def estimate_remaining_time(self, remaining_tasks):
        if len(self.times) == 0:
            return None
        avg_time_per_task = sum(self.times) / len(self.times)
        return avg_time_per_task * remaining_tasks

# -------------------------------
# Connectivity Checks (Internet Only)
# -------------------------------
def is_internet_available() -> bool:
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

async def monitor_connectivity(connectivity_event: asyncio.Event):
    """
    Monitors internet connectivity every 2 seconds.
    When internet is available, sets the event so workers can proceed.
    If connectivity is lost, pauses task execution.
    """
    was_down = False
    while True:
        internet_ok = await asyncio.to_thread(is_internet_available)
        if internet_ok:
            if not connectivity_event.is_set():
                if was_down:
                    print("Internet is back online. Resuming in 30 seconds...")
                    for i in range(30, 0, -1):
                        print(f"Resuming in {i} seconds...", end="\r")
                        await asyncio.sleep(1)
                    print("\nResuming tasks...")
                connectivity_event.set()
                was_down = False
        else:
            if connectivity_event.is_set():
                print("Internet connectivity lost. Pausing new tasks...")
            connectivity_event.clear()
            was_down = True
        await asyncio.sleep(2)

async def initial_safeguard_check_async():
    """
    Before starting processing, wait until internet connectivity is available.
    """
    while not (await asyncio.to_thread(is_internet_available)):
        print("Waiting for internet connection...")
        await asyncio.sleep(2)

# -------------------------------
# Bitcoin Key and Address Generation
# -------------------------------
class PrivateKey:
    def __init__(self, private_key=None):
        # Initializes the instance and generates a random 32-byte private key if not provided.
        if private_key is None:
            self.private_key = os.urandom(32)
        else:
            self.private_key = private_key
        self.passphrase = None
        self.wif = None

    def from_passphrase(self, passphrase):
        # Generates a private key from a given passphrase using SHA256.
        private_key = hashlib.sha256(passphrase.encode('utf-8')).digest()
        self.private_key = private_key
        self.passphrase = passphrase
        self.wif = None
        return private_key

    def privatekey_to_wif(self, private_key=None, compressed=False):
        # Converts a private key to Wallet Import Format (WIF).
        if private_key is None:
            private_key = self.private_key
        if compressed:
            extended_key = b"\x80" + private_key + b"\x01"
        else:
            extended_key = b"\x80" + private_key
        first_sha256 = hashlib.sha256(extended_key).digest()
        second_sha256 = hashlib.sha256(first_sha256).digest()
        final_key = extended_key + second_sha256[:4]
        wif = base58.b58encode(final_key).decode("utf-8")
        self.wif = wif
        return wif

def private_key_to_public_key(private_key_bytes, compressed=True):
    """
    Derives the public key from a given private key using the SECP256k1 curve.
    If compressed=True, returns the compressed public key.
    """
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if compressed:
        pubkey_bytes = vk.to_string()
        x = pubkey_bytes[:32]
        y = pubkey_bytes[32:]
        prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
        return prefix + x
    else:
        return b'\x04' + vk.to_string()

def public_key_to_address(public_key_bytes):
    """
    Converts a public key to a Bitcoin address.
    Follows the standard process: SHA256 -> RIPEMD160 -> add network byte -> checksum -> Base58 encoding.
    """
    sha256 = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    network_byte = b'\x00'  # Bitcoin mainnet
    extended_key = network_byte + ripemd160
    first_sha = hashlib.sha256(extended_key).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    checksum = second_sha[:4]
    binary_address = extended_key + checksum
    address = base58.b58encode(binary_address).decode('utf-8')
    return address

# -------------------------------
# Asynchronous Balance Check
# -------------------------------
async def check_balance(address: str, connectivity_event: asyncio.Event) -> tuple[bool, str]:
    """
    Waits for internet connectivity then runs the balance check via Electrum.
    """
    await connectivity_event.wait()
    try:
        proc = await asyncio.create_subprocess_exec(
            electrum_path, 'getaddressbalance', address,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return True, stdout.decode().strip()
        else:
            return False, stderr.decode().strip()
    except Exception as e:
        return False, str(e)

async def worker(wallet: tuple[str, str], connectivity_event: asyncio.Event, semaphore: asyncio.Semaphore) -> tuple[bool, str, str, str]:
    """
    Worker that checks the balance of a given wallet.
    wallet: tuple containing (address, wif)
    """
    address, wif = wallet
    async with semaphore:
        success, message = await check_balance(address, connectivity_event)
        return success, address, wif, message

# -------------------------------
# Logging and Result Processing
# -------------------------------
def log_result(result: tuple[bool, str, str, str], counter: list, time_estimator: TimeEstimator):
    success, address, wif, message = result
    print("-" * 60)
    if success:
        try:
            balance_info = json.loads(message)
            confirmed = float(balance_info.get('confirmed', 0))
            log_message = f"Address: {address} | Balance: {confirmed} BTC"
            print(log_message)
            if confirmed > 0:
                # Append the positive balance result (public address and WIF) to CSV.
                with open(positive_balance_csv, 'a') as f:
                    f.write(f"{address},{wif}\n")
                print("Positive balance found! Logged wallet to CSV.")
            else:
                print("No balance for this wallet.")
        except json.JSONDecodeError as e:
            print(f"Error parsing balance for {address}: {str(e)}")
    else:
        print(f"Error checking {address}: {message}")
    counter[0] -= 1
    elapsed_time = time.time() - time_estimator.start_time
    time_estimator.start_time = time.time()
    time_estimator.update(elapsed_time)
    remaining_time = time_estimator.estimate_remaining_time(counter[0])
    if remaining_time is not None:
        remaining_hours = int(remaining_time // 3600)
        remaining_minutes = int((remaining_time % 3600) // 60)
        print(f"Remaining wallets to process: {counter[0]} - Estimated remaining time: {remaining_hours}H {remaining_minutes}MN")
    else:
        print(f"Remaining wallets to process: {counter[0]} - Remaining time under calculation")

# -------------------------------
# Main Asynchronous Function
# -------------------------------
async def main():
    print("Starting the wallet balance checker script.")
    await initial_safeguard_check_async()

    # Create and start the connectivity monitor.
    connectivity_event = asyncio.Event()
    connectivity_event.set()  # Assume connectivity is initially available.
    monitor_task = asyncio.create_task(monitor_connectivity(connectivity_event))

    batch_number = 1
    while True:
        print("\n" + "="*80)
        print(f"Starting batch {batch_number} of wallet generation and balance checking.")
        num_wallets = 50  # Define the number of wallets per batch.
        wallets = []
        for i in range(num_wallets):
            pk = PrivateKey()
            wif = pk.privatekey_to_wif(compressed=True)
            pubkey = private_key_to_public_key(pk.private_key, compressed=True)
            address = public_key_to_address(pubkey)
            wallets.append((address, wif))
            print(f"Generated wallet {i+1}: Address: {address}")
        total_wallets = len(wallets)
        print(f"Total wallets to process in batch {batch_number}: {total_wallets}")

        counter = [total_wallets]
        time_estimator = TimeEstimator()

        # Limit concurrency (e.g., 10 simultaneous subprocesses).
        semaphore = asyncio.Semaphore(10)
        tasks = [worker(wallet, connectivity_event, semaphore) for wallet in wallets]

        # Process tasks as they complete.
        for future in asyncio.as_completed(tasks):
            result = await future
            log_result(result, counter, time_estimator)

        print(f"Batch {batch_number} completed. Proceeding to new batch...")
        batch_number += 1

    # This code is unreachable in this infinite loop but kept for clean shutdown.
    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        pass

if __name__ == '__main__':
    asyncio.run(main())