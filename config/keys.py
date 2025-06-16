import os

# Generate or replace with a secure 16-byte key
ENCRYPTION_KEY = os.urandom(16) if not hasattr(__import__('__main__'), 'ENCRYPTION_KEY') else b'your-16-byte-key'