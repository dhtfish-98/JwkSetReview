import unittest, json, base64, hashlib, tempfile, pathlib, datetime, copy, subprocess, sys, os, struct
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa
from jwk_set_review import audit
from jwk_set_review.common import ReviewError,load,read
UTC=datetime.timezone.utc
def enc(b):return base64.b64encode(b).decode()
def url(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def pemkey(k):return k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def certs(leaf_extensions=(),issuer_extensions=()):
    now=datetime.datetime.now(UTC).replace(microsecond=0);issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);leaf_key=ed25519.Ed25519PrivateKey.generate()
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Review CA')])
    ku=x509.KeyUsage(True,False,False,False,False,True,True,False,False)
    builder=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(issuer_key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(ku,True).add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),False)
    for ext,critical in issuer_extensions:builder=builder.add_extension(ext,critical)
    issuer=builder.sign(issuer_key,hashes.SHA256())
    builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.invalid')])).issuer_name(subject).public_key(leaf_key.public_key()).serial_number(10).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
    for ext,critical in leaf_extensions:builder=builder.add_extension(ext,critical)
    leaf=builder.sign(issuer_key,hashes.SHA256());return now,issuer_key,issuer,leaf_key,leaf
def cpem(c):return c.public_bytes(serialization.Encoding.PEM).decode()
def save_example(d):
    if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':return
    out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True)
    (out/'valid.json').write_text(json.dumps(d,indent=2)+'\n')
class CommonTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_input(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(ReviewError):load(raw)
    def test_input_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t);(p/'file').write_text('x');(p/'link').symlink_to(p/'file');os.mkfifo(p/'pipe')
            for q in (p/'link',p/'pipe'):
                with self.assertRaises((ReviewError,OSError)):read(str(q))
    def test_missing_fields_and_cli_exit(self):
        with self.assertRaises((ReviewError,KeyError)):audit({})
        proc=subprocess.run([sys.executable,'-m','jwk_set_review','-'],input=b'{}',capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,1);self.assertEqual(json.loads(proc.stdout)['status'],'FAIL');self.assertFalse(json.loads(proc.stdout)['complete'])

class JwkTests(unittest.TestCase):
    def setUp(self):
        k=ed25519.Ed25519PrivateKey.generate();pub=k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw);self.d={'jwks':{'keys':[{'kty':'OKP','kid':'synthetic-signing-key','alg':'EdDSA','crv':'Ed25519','x':url(pub),'use':'sig','key_ops':['verify']}]}}
    def test_valid_public_audit(self):self.assertFalse(audit(self.d)['verified']);save_example(self.d)
    def test_private_duplicate_algorithm_and_bad_encoding(self):
        mutations=[lambda j:j.update(d='private'),lambda j:j.update(alg='HS256'),lambda j:j.update(x='!!!'),lambda j:j.update(key_ops=['sign'])]
        for change in mutations:
            d=copy.deepcopy(self.d);change(d['jwks']['keys'][0])
            with self.assertRaises(ReviewError):audit(d)
        d=copy.deepcopy(self.d);d['jwks']['keys'].append(d['jwks']['keys'][0])
        with self.assertRaises(ReviewError):audit(d)
    def test_small_order_ed25519(self):
        for point in (bytes(32),b'\x01'+bytes(31),bytes.fromhex('ec'+'ff'*30+'7f')):
            d=copy.deepcopy(self.d);d['jwks']['keys'][0]['x']=url(point)
            with self.assertRaises(ReviewError):audit(d)
    def test_ec_point_and_rsa(self):
        key=ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers();j={'kty':'EC','kid':'ec','alg':'ES256','crv':'P-256','x':url(key.x.to_bytes(32,'big')),'y':url(key.y.to_bytes(32,'big'))};self.assertEqual(audit({'jwks':{'keys':[j]}})['status'],'PASS');j['y']=url(bytes(32))
        with self.assertRaises(ReviewError):audit({'jwks':{'keys':[j]}})
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_numbers();j={'kty':'RSA','kid':'rsa','alg':'RS256','n':url(key.n.to_bytes(256,'big')),'e':url(key.e.to_bytes(3,'big'))};self.assertEqual(audit({'jwks':{'keys':[j]}})['status'],'PASS')

if __name__=="__main__":unittest.main()
