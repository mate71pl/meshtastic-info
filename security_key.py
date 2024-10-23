##############################################################################################
## This script is used to generate new key pairs or derive a public key from a private one, ##
## needed in case of loss of the original keys in Firmware version 2.5.0 or higher.         ##
## Installing pynacl may be required (pip install pynacl).                                  ##
##############################################################################################

import nacl.bindings
import base64
import sys

def generate_key_pair():
    # Generate a new X25519 key pair
    private_key_bytes = nacl.bindings.randombytes(32)
    public_key_bytes = nacl.bindings.crypto_scalarmult_base(private_key_bytes)

    private_key_base64 = base64.b64encode(private_key_bytes).decode('utf-8')
    public_key_base64 = base64.b64encode(public_key_bytes).decode('utf-8')

    print("Generated key pair:")
    print("Private key:", private_key_base64)
    print("Public key:", public_key_base64)

def generate_public_key_from_private(private_key_base64):
    try:
        # Decode the private key from Base64
        private_key_bytes = base64.b64decode(private_key_base64)

        # Generate the public key
        public_key_bytes = nacl.bindings.crypto_scalarmult_base(private_key_bytes)

        # Convert the public key to Base64
        public_key_base64 = base64.b64encode(public_key_bytes).decode('utf-8')

        print("Public key:", public_key_base64)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

# Menu for selecting the action
print("What would you like to do?")
print("1. Generate a new key pair")
print("2. Generate a public key from an existing private key")
choice = input("Choose an option (1/2): ")

if choice == "1":
    generate_key_pair()
elif choice == "2":
    private_key_base64 = input("Enter the private key in Base64: ")
    generate_public_key_from_private(private_key_base64)
else:
    print("Invalid choice.")
    sys.exit(1)
