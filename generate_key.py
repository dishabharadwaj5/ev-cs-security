
from Crypto.PublicKey import RSA

# Generate 2048-bit RSA key pair
key = RSA.generate(2048)

# Save the private key in PEM format
with open("cs_private_key.pem", "wb") as f:
    f.write(key.export_key(format='PEM'))

# Save the public key in PEM format
with open("cs_public_key.pem", "wb") as f:
    f.write(key.publickey().export_key(format='PEM'))

print(" RSA key pair generated in PEM format")
