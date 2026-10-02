from .common import *
from .crypto import *
def audit(d):
    fields(d,['jwks'],['minimum_rsa_bits']);fields(d['jwks'],['keys']);minbits=integer(d.get('minimum_rsa_bits',2048),2048,8192)
    keys=seq(d['jwks']['keys'],128);need(keys,"empty key set");seen=set();material=set();out=[]
    for j in keys:
        obj(j);need(not any(k in j for k in ('d','p','q','dp','dq','qi','oth','k')),"private or symmetric key material forbidden")
        kid=string(j.get('kid'),256);need(kid and kid not in seen,"missing or duplicate key identifier");seen.add(kid)
        typ=j.get('kty');use=j.get('use','sig');need(use=='sig',"only signature public keys supported")
        if 'key_ops' in j:need(seq(j['key_ops'],8)==['verify'],"public key operations must be verify only")
        common=['kty','kid','alg'];opt=['use','key_ops']
        alg=j.get('alg')
        if typ=='RSA':
            fields(j,common+['n','e'],opt);need(alg in ('RS256','RS384','RS512','PS256','PS384','PS512'),"RSA algorithm mismatch")
            nraw=b64(j['n'],True,1024);eraw=b64(j['e'],True,8);need(nraw and eraw and nraw[0]!=0 and eraw[0]!=0,"nonminimal RSA integer")
            n=int.from_bytes(nraw,'big');e=int.from_bytes(eraw,'big');need(n.bit_length()>=minbits and n&1 and e>=65537 and e&1,"weak RSA public key")
            try:k=rsa.RSAPublicNumbers(e,n).public_key()
            except ValueError:raise ReviewError("invalid RSA public key") from None
        elif typ=='EC':
            fields(j,common+['crv','x','y'],opt);curves={'P-256':(ec.SECP256R1,32,'ES256'),'P-384':(ec.SECP384R1,48,'ES384'),'P-521':(ec.SECP521R1,66,'ES512')}
            need(j['crv'] in curves,"unsupported curve");cls,size,expected=curves[j['crv']];need(alg==expected,"curve and algorithm mismatch")
            x=b64(j['x'],True,66);y=b64(j['y'],True,66);need(len(x)==len(y)==size,"invalid EC coordinate length")
            try:k=ec.EllipticCurvePublicNumbers(int.from_bytes(x,'big'),int.from_bytes(y,'big'),cls()).public_key()
            except ValueError:raise ReviewError("EC point is not on curve") from None
        elif typ=='OKP':
            fields(j,common+['crv','x'],opt);need(j['crv']=='Ed25519' and alg=='EdDSA',"unsupported OKP algorithm");x=b64(j['x'],True,32);need(len(x)==32 and valid_ed_point(x),"noncanonical, off-curve or small-order Ed25519 public key");k=ed25519.Ed25519PublicKey.from_public_bytes(x)
        else:raise ReviewError("unsupported key type")
        fp=fingerprint(k);need(fp not in material,"same public key has multiple identities");material.add(fp)
        out.append({'key_id_sha256':hashlib.sha256(kid.encode()).hexdigest(),'key_type':typ,'algorithm':alg,'public_key_sha256':fp})
    return report(verified=False,trust='not established: static public key audit',keys=out)
