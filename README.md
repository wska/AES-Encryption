# AES-Encryption
AES 128-bit encryption.

Takes the input and uses the first 16 bytes as a key. The remaining content of the file will be encrypted 16 bytes as a time in blocks. Padding is not done automatically, and as such each block needs to consist of exactly 16 bytes.
