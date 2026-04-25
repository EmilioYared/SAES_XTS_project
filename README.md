*By Antonio Youssef and Emilio Yared*

# Project Structure and Running

## What Each Folder Contains

- `algorithm/`: Core cryptographic code, including S-AES, SAES-XTS, and the SAES cryptanalysis utilities.
- `helpers/`: Shared support code for bit, byte, block, and state formatting/conversion.
- `tests/`: Unit tests for the algorithm layer, helpers, cryptanalysis flow, and the web app integration points.
- `webapp/`: The Streamlit application, including the landing page, educational wizard, encrypt/decrypt tools, and cryptanalysis views.

## How to Run

- Start the web app:

```powershell
streamlit run webapp/app.py
```

- Run the main test suites used in this project:

```powershell
python -m unittest tests.test_cryptanalysis tests.test_webapp -v
```


This project implements an SAES-XTS mode, which is basically a way to use the simplified version of AES (S-AES) 
to securely encrypt larger data. Since S-AES only works on very 
small blocks (16 bits), we need a mode like XTS to handle real inputs like files or longer messages.

The idea behind this implementation is to follow the XEX structure, which works in three steps for each block:
1. First, the plaintext block is XORed with a value called the tweak
2. Then, the result is encrypted using S-AES with the main key
3. Finally, the output is XORed again with the same tweak

So P xor T → encrypt → xor T → C
---

# Code Flow and Main Functions

## 1. Entry Point: XTS Encryption/Decryption

- The main entry points for encrypting or decrypting a message are:
	- `encrypt_message(plaintext, data_key, tweak_key, data_unit)` in [algorithm/xts.py](xts.py)
	- `decrypt_message(ciphertext, data_key, tweak_key, data_unit)` in [algorithm/xts.py](xts.py)

#### These functions:
- Take a byte string (the message), a data key, a tweak key, and a data unit (like a sector number).
- Call `encrypt_message_with_trace` or `decrypt_message_with_trace` for detailed tracing, but return only the ciphertext or plaintext.

## 2. Splitting and Preparing Blocks

- The message is split into 2-byte (16-bit) blocks using `split_blocks`.
- The tweak for the first block is derived by encrypting the `data_unit` with the `tweak_key` using `derive_initial_tweak`.

## 3. Block Processing Loop

- For each block:
	- The tweak is updated for each block using `multiply_tweak_by_alpha`.
	- Each block is processed by `_crypt_full_block`:
		- The block is XORed with the tweak (pre-whitening).
		- The result is encrypted (or decrypted) with S-AES using the data key.
		- The output is XORed again with the tweak (post-whitening).
		- The tweak is updated for the next block.

## 4. S-AES Block Encryption/Decryption

- The S-AES block cipher is implemented in [algorithm/saes.py](saes.py):
	- `encrypt_block_with_trace` and `decrypt_block_with_trace` perform the full round transformations and return intermediate values for tracing.
	- `encrypt_block` and `decrypt_block` are simple wrappers that return only the final ciphertext or plaintext.

- The S-AES round operations (substitute, shift rows, mix columns, etc.) are in [algorithm/round_ops.py](round_ops.py).

- The key schedule (expanding the 16-bit key into round keys) is in [algorithm/key_schedule.py](key_schedule.py).

## 5. Ciphertext Stealing (CTS) for Partial Blocks

- If the last block is not a full 2 bytes, ciphertext stealing is used:
	- `_encrypt_with_ciphertext_stealing` and `_decrypt_with_ciphertext_stealing` handle this case.
	- The last two blocks are processed specially so that no padding is needed.

## 6. Helpers and Utilities

- [helpers/bit_utils.py](../helpers/bit_utils.py), [helpers/block_utils.py](../helpers/block_utils.py), etc., provide bit/byte manipulation, validation, and conversion functions.

---

## Example Flow (Encryption)

1. **User calls** `encrypt_message(plaintext, data_key, tweak_key, data_unit)` in [algorithm/xts.py](xts.py).
2. **Splitting:** The plaintext is split into 2-byte blocks.
3. **Tweak:** The initial tweak is derived by encrypting the data_unit with the tweak_key.
4. **Block Loop:** For each block:
	 - XOR with tweak.
	 - Encrypt with S-AES (`encrypt_block_with_trace` in [algorithm/saes.py](saes.py)).
	 - XOR with tweak again.
	 - Update tweak for next block.
5. **Partial Block:** If the last block is partial, ciphertext stealing is used.
6. **Result:** All ciphertext blocks are joined and returned.

---

## Example Flow (Decryption)

1. **User calls** `decrypt_message(ciphertext, data_key, tweak_key, data_unit)` in [algorithm/xts.py](xts.py).
2. **Splitting:** The ciphertext is split into 2-byte blocks.
3. **Tweak:** The initial tweak is derived as in encryption.
4. **Block Loop:** For each block:
	 - XOR with tweak.
	 - Decrypt with S-AES (`decrypt_block_with_trace`).
	 - XOR with tweak again.
	 - Update tweak for next block.
5. **Partial Block:** If the last block is partial, ciphertext stealing is used.
6. **Result:** All plaintext blocks are joined and returned.

---

## File Responsibilities

- **xts.py:** Implements the XTS mode, block processing, tweaks, and ciphertext stealing.
- **saes.py:** Implements the S-AES block cipher (encryption/decryption of 16-bit blocks).
- **key_schedule.py:** Expands the 16-bit key into round keys for S-AES.
- **round_ops.py:** Implements S-AES round operations (substitute, shift rows, mix columns, etc.).
- **helpers/**: Utility functions for bit/byte operations.

---

## How to Read the Code

- Start at [algorithm/xts.py](xts.py) with `encrypt_message` or `decrypt_message`.
- Follow the block processing and see how each block is handled.
- Dive into [algorithm/saes.py](saes.py) to see how a single block is encrypted/decrypted.
- Check [algorithm/key_schedule.py](key_schedule.py) and [algorithm/round_ops.py](round_ops.py) for the details of key expansion and round transformations.

---

