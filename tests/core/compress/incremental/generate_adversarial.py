import pathlib,zlib,json,hashlib
root = pathlib.Path(__file__).resolve().parent / 'testdata'
class Bits:
 def __init__(self): self.b=[]
 def put(self,v,n): self.b.extend((v>>i)&1 for i in range(n))
 def code(self,v,n):
  for i in range(n-1,-1,-1): self.put((v>>i)&1,1)
 def data(self): return bytes(sum(x<<i for i,x in enumerate(self.b[j:j+8])) for j in range(0,len(self.b),8))
def fixedsym(b,s):
 if s<=143:b.code(0x30+s,8)
 elif s<=255:b.code(0x190+s-144,9)
 elif s<=279:b.code(s-256,7)
 else:b.code(0xc0+s-280,8)
def fixed():
 b=Bits();b.put(3,3);return b
vectors={'stored-complement':bytes([1,1,0,1,0,65])}
for s in [286,287]:
 b=fixed();fixedsym(b,s);fixedsym(b,256);vectors[f'literal-{s}']=b.data()
b=fixed();fixedsym(b,257);b.code(0,5);fixedsym(b,256);vectors['distance-before-history']=b.data()
for s in [30,31]:
 b=fixed();fixedsym(b,65);fixedsym(b,257);b.code(s,5);fixedsym(b,256);vectors[f'distance-{s}']=b.data()
def dynamic(lengths):
 b=Bits();b.put(5,3);b.put(0,5);b.put(0,5);b.put(len(lengths)-4,4)
 for n in lengths:b.put(n,3)
 return b
vectors['empty-code-tree']=dynamic([0,0,0,0]).data()
vectors['oversubscribed-code-tree']=dynamic([1,1,1,0]).data()
vectors['incomplete-code-tree']=dynamic([0,0,0,2]).data()
b=dynamic([1,0,0,1]);b.code(1,1);vectors['repeat-16-first']=b.data()
b=dynamic([0,0,1,1])
for _ in range(2):b.code(1,1);b.put(127,7)
vectors['repeat-overflow']=b.data()
b=dynamic([0,0,0,1]+[0]*13+[1])
for s in range(258):b.code(1 if s in [65,66] else 0,1)
vectors['missing-end-code']=b.data()
manifest={}
for name,data in vectors.items():
 try:zlib.decompress(data,-15)
 except zlib.error as e: rejected=str(e)
 else:raise RuntimeError('unexpected valid '+name)
 file='raw-invalid-'+name+'.deflate';(root/file).write_bytes(data)
 manifest[file]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'python_zlib_rejection':rejected}
(root/'raw-invalid-manifest.json').write_text(json.dumps({'generator':'Independent Python bitwriter; RFC1951 canonical fixed codes and explicit dynamic headers','zlib_version':zlib.ZLIB_VERSION,'files':manifest},indent=2)+'\n')
print(json.dumps(manifest,indent=2))
