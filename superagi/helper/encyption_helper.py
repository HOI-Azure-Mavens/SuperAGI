import base64
import os
from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
from superagi.config.config import get_config
from superagi.lib.logger import logger

# Get encryption key from env or config
key = os.getenv('ENCRYPT_KEY') or get_config("ENCRYPTION_KEY")
if key is None:
   logger.error("Encryption key not found in environment or config")
   key = "mysecretencryptionkey123456789012345"  # Default key for development

# Ensure key is exactly 32 bytes
if len(key) < 32:
   key = key.ljust(32, '0')
elif len(key) > 32:
   key = key[:32]

# Encode and prepare key for Fernet
key = key.encode("utf-8")
key = base64.urlsafe_b64encode(key)
cipher_suite = Fernet(key)

def encrypt_data(data):
   """Encrypts data using Fernet cipher suite"""
   encrypted_data = cipher_suite.encrypt(data.encode())
   return encrypted_data.decode()

def decrypt_data(encrypted_data):
   """Decrypts data using Fernet cipher suite"""
   decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
   return decrypted_data.decode()

def is_encrypted(value):
   """Checks if value is encrypted"""
   try:
       f = Fernet(key)
       f.decrypt(value)
       return True
   except (InvalidToken, InvalidSignature):
       return False
   except (ValueError, TypeError):
       return False
