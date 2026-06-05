import json, sys
sys.path.insert(0, '.')
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from crypto_utils import diploma_to_canonical_bytes, hash_hex, build_certificate

priv = serialization.load_pem_private_key(open('fake_private.pem','rb').read(), password=None)

diploma = {
    'student_name':    'Rayah Mohammed',
    'student_id':      '441349299',
    'degree':          'Doctor of Philosophy',
    'graduation_date': '2019-03-01',
    'university':      'Umm Al-Qura University',
    'issuer':          'Office of the Registrar',
    'diploma_id':      'UQU-2019-FAKE-001',
}

doc_bytes = diploma_to_canonical_bytes(diploma)
sig_hex   = priv.sign(doc_bytes, ec.ECDSA(hashes.SHA256())).hex()
cert      = build_certificate(diploma, sig_hex, 'UQU')

open('signatures/fake.cert.json','w').write(json.dumps(cert, indent=2))
print('Fake certificate saved: signatures/fake.cert.json')
print('Document hash:', hash_hex(doc_bytes)[:40]+'...')