import hashlib,hmac,json
seed=bytes(range(32));scope={'container':'iCloud.test','environment':'Development','account':'a'}
salt=hashlib.sha256(json.dumps(scope,sort_keys=True,separators=(',',':')).encode()).digest()
p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
g=(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
def add(a,b):
 if a is None:return b
 if b is None:return a
 x,y=a;u,v=b
 if x==u and (y+v)%p==0:return None
 m=((3*x*x-3)*pow(2*y,-1,p) if a==b else (v-y)*pow(u-x,-1,p))%p
 z=(m*m-x-u)%p
 return z,(m*(x-z)-y)%p
def public(k):
 a=None;b=g
 while k:
  if k&1:a=add(a,b)
  b=add(b,b);k>>=1
 return '04'+''.join(x.to_bytes(32,'big').hex() for x in a)
prk=hmac.new(salt,seed,hashlib.sha256).digest()
for purpose in ['agreement','signing']:
 counter=0
 while True:
  raw=hmac.new(prk,f'2ndpass/offline-recovery/v1/{purpose}/{counter}'.encode()+b'\x01',hashlib.sha256).digest()
  scalar=int.from_bytes(raw,'big')
  if 0<scalar<n:break
  counter+=1
 print(purpose,public(scalar))
print('checksum',hashlib.sha256(b'2ndpass/recovery-code/v1'+seed).hexdigest()[:8].upper())
