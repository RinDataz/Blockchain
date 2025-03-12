import hashlib  # Library for hashing functions
import random  # Library for generating random numbers
import binascii  # Library for binary-to-ASCII conversion
import datetime  # Library for handling date and time
import collections  # Library for ordered dictionaries
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # RSA encryption and padding
from cryptography.hazmat.primitives import serialization, hashes  # Serialization and hashing functions

#1.	The Client class provides the necessary functionality to generate and use cryptographic keys for signing.
# Client Class: Represents a user in the blockchain network.
# Each client has a unique RSA (encryption method) key pair (public and private keys).
class Client:
    def __init__(self, name):
        self.name = name
        # Generate a private RSA key for the client.
        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        # Derive the corresponding public key.
        self._public_key = self._private_key.public_key()

    @property
    def identity(self):
        # Returns the public key in a serialized hexadecimal format as the client's identity.
        pubkey_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return binascii.hexlify(pubkey_bytes).decode('ascii')

    def sign(self, message):
        # Signs a message using the client's private key.
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

# Transaction Class: Represents a transaction between clients.
class Transaction:
    def __init__(self, sender, recipient, value):
        self.sender = sender  # Sender client
        self.recipient = recipient  # Recipient's identity (public key)
        self.value = value  # Transaction amount
        self.time = datetime.datetime.now()  # Timestamp of the transaction
        self.signature = None  # Placeholder for the transaction signature

    def to_dict(self):
        # Converts the transaction details into an ordered dictionary.
        identity = "Genesis" if self.sender.name == "Genesis" else self.sender.identity
        return collections.OrderedDict({
            'sender': identity,
            'recipient': self.recipient,
            'value': self.value,
            'time': self.time.isoformat()
        })

    def sign_transaction(self):
        # Signs the transaction using the sender's private key.
        if self.sender.name == "Genesis":
            return None  # Genesis transactions are not signed.
        else:
            message = str(self.to_dict())
            self.signature = self.sender.sign(message)
            return self.signature

# Block Class: Represents a block in the blockchain.
class Block:
    def __init__(self, transactions, previous_hash):
        self.transactions = transactions  # List of transactions included in the block.
        self.previous_hash = previous_hash  # Hash of the previous block.
        self.nonce = random.randint(0, 2**32)  # Random nonce value for mining.
        self.block_hash = self.calculate_hash()  # Compute initial block hash.

    def calculate_hash(self):
        # Computes the SHA-256 hash of the block's contents.
        block_string = str(self.transactions) + self.previous_hash + str(self.nonce)
        return hashlib.sha256(block_string.encode()).hexdigest()

# Blockchain Class: Represents the blockchain itself.
class Blockchain:
    def __init__(self):
        self.chain = []  # List of blocks in the blockchain.

    def add_block(self, block):
        # Adds a mined block to the blockchain.
        self.chain.append(block)

    def dump_chain(self):
        # Prints the entire blockchain in a readable format.
        for i, block in enumerate(self.chain):
            print(f"Block {i+1}:")
            print("Hash:", block.block_hash)
            print("Previous Hash:", block.previous_hash)
            print("Nonce:", block.nonce)
            for transaction in block.transactions:
                print(transaction.to_dict())
            print("---")

# Mining Function: Adjusts the nonce until a valid hash is found.
def mine_block(block, difficulty=4):
    prefix = '0' * difficulty  # Defines the required prefix for proof of work.
    while not block.block_hash.startswith(prefix):
        block.nonce += 1  # Increment nonce value.
        block.block_hash = block.calculate_hash()  # Recalculate hash.
    return block

# Creating Clients (Users in the blockchain network)
Dinesh = Client("Dinesh")
Ramesh = Client("Ramesh")
Seema = Client("Seema")
Vijay = Client("Vijay")
genesis_client = Client("Genesis")  # Special client for the genesis block.

# Creating Transactions
transactions = [
    Transaction(Dinesh, Ramesh.identity, 15.0),  # Dinesh sends 15 to Ramesh
    Transaction(Dinesh, Seema.identity, 6.0),  # Dinesh sends 6 to Seema
    Transaction(Ramesh, Vijay.identity, 2.0)  # Ramesh sends 2 to Vijay
]

# Signing Transactions
for transaction in transactions:
    transaction.sign_transaction()

# Creating Genesis Block (First Block in the Blockchain)
genesis_transaction = Transaction(genesis_client, Dinesh.identity, 100.0)  # Initial allocation
genesis_transaction.sign_transaction()
genesis_block = Block([genesis_transaction], "0")  # First block with no previous hash

# Creating Blockchain and Adding Blocks
blockchain = Blockchain()
blockchain.add_block(genesis_block)  # Add genesis block to blockchain

# Mine and Add New Blocks to the Blockchain
for transaction in transactions:
    new_block = Block([transaction], blockchain.chain[-1].block_hash)  # Create new block
    mined_block = mine_block(new_block)  # Mine the block
    blockchain.add_block(mined_block)  # Add mined block to blockchain

# Display the Final Blockchain
blockchain.dump_chain()
print("Dinesh: ",Dinesh.identity, Dinesh.name)