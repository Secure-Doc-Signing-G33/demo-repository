from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

private = ec.generate_private_key(ec.SECP256K1())
public  = private.public_key()

open('fake_private.pem','wb').write(private.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
))
open('fake_public.pem','wb').write(public.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
))
print('Attacker creat a fake keys : fake_private.pem / fake_public.pem')