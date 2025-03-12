import hashlib
import random
import string
import json
import binascii
import numpy as np
import logging
import datetime
import collections

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class Client:
    def __init__(self):
        # Generate a more secure RSA private key (2048-bit instead of 1024-bit)
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048  # Upgraded for security
        )
        # Get the public key from the private key
        self._public_key = self._private_key.public_key()

    @property
    def identity(self):
        # Export the public key in DER format and convert to string
        pubkey_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return binascii.hexlify(pubkey_bytes).decode('ascii')

    def sign(self, message):
        # Sign the message using the private key
        message = message.encode('utf-8')
        signature = self._private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return binascii.hexlify(signature).decode('ascii')


class Transaction:
    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.time = datetime.datetime.now()
        self.signature = None  # Store signature

    def to_dict(self):
        identity = "Genesis" if self.sender == "Genesis" else self.sender.identity
        return collections.OrderedDict({
            'sender': identity,
            'recipient': self.recipient,
            'value': self.value,
            'time': self.time.isoformat()
        })

    def sign_transaction(self):
        if self.sender == "Genesis":
            return None
        else:
            message = str(self.to_dict())
            self.signature = self.sender.sign(message)  # Store the signature
            return self.signature


def display_transaction(transaction):
    transaction_dict = transaction.to_dict()  # Fix variable name
    print("sender: " + transaction_dict['sender'])
    print('-----')
    print("recipient: " + transaction_dict['recipient'])
    print('-----')
    print("value: " + str(transaction_dict['value']))
    print('-----')
    print("time: " + str(transaction_dict['time']))
    print('-----')
    print("signature: " + str(transaction.signature))  # Show signature if available
    print('--------------')


# Create Clients
Dinesh = Client()
Ramesh = Client()
Seema = Client()
Vijay = Client()

# Transactions List
transactions = [
    Transaction(Dinesh, Ramesh.identity, 15.0),
    Transaction(Dinesh, Seema.identity, 6.0),
    Transaction(Ramesh, Vijay.identity, 2.0),
    Transaction(Seema, Ramesh.identity, 4.0),
    Transaction(Vijay, Seema.identity, 7.0),
    Transaction(Ramesh, Seema.identity, 3.0),
    Transaction(Seema, Dinesh.identity, 8.0),
    Transaction(Seema, Ramesh.identity, 1.0),
    Transaction(Vijay, Dinesh.identity, 5.0),
    Transaction(Vijay, Ramesh.identity, 3.0)
]

# Sign Transactions
for transaction in transactions:
    transaction.sign_transaction()
    display_transaction(transaction)


