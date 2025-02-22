# Bitcoin-generator-and-balance-
Batch Generate addresses, check their balance on electrum

Disclaimer --> For educational content only


# Bitcoin Wallet Balance Checker

This repository contains a Python script that:

- **Generates Bitcoin Wallets:** Automatically creates random Bitcoin wallets (address and private key in Wallet Import Format).
- **Checks Wallet Balances:** Uses Electrum via asynchronous subprocess calls to check each wallet's balance.
- **Monitors Connectivity:** Continuously checks for internet connectivity and pauses/resumes balance checks as needed.
- **Reports Progress:** Provides real-time print statements showing wallet generation, balance results, and estimated time remaining.
- **Logs Positive Balances:** Appends any wallet with a positive balance (address and corresponding private key) to a CSV file.

## How to Use

1. **Dependencies:**  
   Ensure you have Python and the necessary packages installed (e.g., `asyncio`, `subprocess`, `ecdsa`, etc.). Also, download the portable Electrum client.

2. **Configuration:**  
   Update the file paths in the script for:
   - electrum-4.5.5-portable.exe
   - CSV output file for wallets with a positive balance

3. **Run the Script:**  

   Execute the script in your terminal:
   ```bash
   python btc_generator_checker.py
