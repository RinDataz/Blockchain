import hashlib
import random
import binascii
import collections
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Defining the Client Class
class Client:
    def __init__(self, name):
        self.name = name
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self._public_key = self._private_key.public_key()

    @property
    def identity(self):
        pubkey_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return binascii.hexlify(pubkey_bytes).decode('ascii')

    def sign(self, message):
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

# Class Definition Transactions
class Transaction:
    def __init__(self, sender, recipient, value):
        self.sender = sender  # Should be a Client instance
        self.recipient = recipient
        self.value = value
        self.time = datetime.datetime.now()
        self.signature = None

    def to_dict(self):
        identity = "Genesis" if self.sender.name == "Genesis" else self.sender.identity
        return collections.OrderedDict({
            'sender': identity,
            'recipient': self.recipient,
            'value': self.value,
            'time': self.time.isoformat()
        })

    def sign_transaction(self):
        if self.sender.name == "Genesis":
            return None
        else:
            message = str(self.to_dict())
            self.signature = self.sender.sign(message)
            return self.signature

# Function to Display Transaction
def display_transaction(transaction):
    transaction_dict = transaction.to_dict()
    print("Sender: " + transaction_dict['sender'])
    print("Recipient: " + transaction_dict['recipient'])
    print("Value: " + str(transaction_dict['value']))
    print("Time: " + str(transaction_dict['time']))
    print("Signature: " + str(transaction.signature))
    print("--------------")

# Class Block
class Block:
    def __init__(self, transactions, previous_hash):
        self.transactions = transactions  # Store verified transactions
        self.previous_hash = previous_hash  # Hash of the previous block
        self.nonce = random.randint(0, 2**32)  # Random nonce for proof-of-work
        self.block_hash = self.calculate_hash()  # Calculate hash of the block

    def calculate_hash(self):
        block_string = str(self.transactions) + self.previous_hash + str(self.nonce)
        return hashlib.sha256(block_string.encode()).hexdigest()

# Creating Client Instances
Dinesh = Client("Dinesh")
Ramesh = Client("Ramesh")
Seema = Client("Seema")
Vijay = Client("Vijay")
genesis_client = Client("Genesis")

# Creating and Signing Transactions
transactions = [
    Transaction(Dinesh, Ramesh.identity, 15.0),
    Transaction(Dinesh, Seema.identity, 6.0),
    Transaction(Ramesh, Vijay.identity, 2.0),
    Transaction(Seema, Ramesh.identity, 4.0),
    Transaction(Vijay, Seema.identity, 7.0)
]

for transaction in transactions:
    transaction.sign_transaction()
    display_transaction(transaction)

# Creating the Genesis Transaction
genesis_transaction = Transaction(genesis_client, Dinesh.identity, 100.0)
genesis_transaction.sign_transaction()

# Creating the Genesis Block
genesis_block = Block([genesis_transaction], "0")  # Previous hash is '0' for the genesis block
last_block_hash = genesis_block.block_hash  # Store the hash of the genesis block

# Print initial values of the genesis block
print("Genesis Block Initial Values:")
print("Hash:", genesis_block.block_hash)
print("Previous Hash:", genesis_block.previous_hash)
print("Nonce:", genesis_block.nonce)

# Creating Additional Blocks
blockchain = [genesis_block]

# Appending Blocks to the Blockchain
for i in range(3):  # Create 3 additional blocks
    new_block = Block(transactions, blockchain[-1].block_hash)  # Link to the last block
    blockchain.append(new_block)  # Append the new block to the blockchain

# Definition of dump_blockchain Function
def dump_blockchain(blockchain):
    print(f"Number of Blocks: {len(blockchain)}")
    for i, block in enumerate(blockchain):
        print(f"\nBlock {i + 1}:")
        print("Hash:", block.block_hash)
        print("Previous Hash:", block.previous_hash)
        print("Nonce:", block.nonce)
        print("Transactions:")
        for transaction in block.transactions:
            display_transaction(transaction)
        print("--------------")

# Dumping the Blockchain
dump_blockchain(blockchain)