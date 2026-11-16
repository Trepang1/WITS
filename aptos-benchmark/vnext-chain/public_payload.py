"""Public hints for exact-current transcript; all hints are checked in Move."""
import hashlib,json,pathlib,sys
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from edwards_ristretto_encoding import Q,P,D,root,affine,mul,IDENTITY,ed_encode,conversion_hint
def le(n,size=8):return n.to_bytes(size,'little')
def frame(b):return le(len(b))+b
def put(t,l,v):t.extend(le(len(l),4)+l+le(len(v))+v)
def challenge(t,l):
    for i in range(10000):
        pre=bytearray(t);put(pre,b'challenge-label',l);put(pre,b'counter',le(i))
        b=bytearray(hashlib.sha512(pre).digest()[:32]);b[31]&=31;s=int.from_bytes(b,'little')
        if 0<s<Q:put(t,l,b);return s
    raise RuntimeError('finite challenge retries exhausted')
def hash_group(label):
    hints=b''
    for counter in range(64):
        ed=hashlib.sha512(b'WTAS/CPU/Edwards/HashToGroup/v1'+label+le(counter)).digest()[:32]
        enc=int.from_bytes(ed,'little');sign,y=enc>>255,enc&((1<<255)-1)
        if y>=P:hints+=bytes(32);continue
        ratio=(y*y-1)*pow((D*y*y+1)%P,-1,P)%P
        try:x=root(ratio)
        except ValueError:hints+=le(root(2*ratio%P),32);continue
        if x&1!=sign:x=-x%P
        hints+=le(x,32)
        if x==0 and sign:continue
        point=affine(mul(8,(x,y,1,x*y%P)))
        if point==IDENTITY:continue
        out=ed_encode(point);return out,conversion_hint(out),hints
    raise RuntimeError('finite hash-to-group retries exhausted')
def build(data):
    raw=lambda k:bytes.fromhex(data[k]);n=data['n'];proof=raw('proof');sig=raw('signature');k=raw('aggregate_key')
    stmt=raw('statement');t=bytearray();put(t,b'WT-Proof',stmt)
    he,hi,hh=hash_group(b'WT-Blinding-Generator'+stmt+le(0));assert he.hex()==data['H'];put(t,b'H',he)
    put(t,b'A',proof[:32]);lam=challenge(t,b'lambda_key');put(t,b'S',proof[32:64]);y=challenge(t,b'y');z=challenge(t,b'z')
    put(t,b'T1',proof[64:96]);put(t,b'T2',proof[96:128]);x=challenge(t,b'x')
    for l,b in [(b'tau_x',proof[128:160]),(b'mu',proof[160:192]),(b't_hat',proof[192:224])]:put(t,l,b)
    ue,ui,uh=hash_group(b'WT-IPA-Generator'+t);assert ue.hex()==data['U']
    rounds=n.bit_length()-1
    points=[k,sig[:32]]+[proof[i:i+32] for i in range(0,128,32)]+[proof[i:i+32] for i in range(224,224+64*rounds,32)]
    hints=b''.join(conversion_hint(p)for p in points)
    regs=[]
    for i in range(n):
        pk=bytes.fromhex(data['pk'][i]);pop=data['pops'][i];dp=bytes.fromhex(pop['D'])
        p=le(data['weights'][i])+frame(pk)+frame(conversion_hint(pk))+frame(dp)+frame(conversion_hint(dp))+frame(bytes.fromhex(pop['response']))
        for family in ['g','h']:
            ed,ih,gh=hash_group(f'{family}/{i}'.encode());assert ed.hex()==data[family][i]
            p+=frame(ed)+frame(ih)+frame(gh)
        regs.append(p)
    h=lambda b:'hex:'+b.hex()
    begin=[f'u64:{n}',f"u64:{data['threshold']}",h(raw('combiner_pk')),h(conversion_hint(raw('combiner_pk')))]
    args=[h(k),h(sig),h(raw('message')),f"u64:{data['total']}",h(proof),h(hints),h(he),h(hi),h(hh),h(ue),h(ui),h(uh),h(raw('combiner_signature'))]
    return dict(n=n,begin_args=begin,registration_batches=[h(b''.join(regs[i:i+2]))for i in range(0,n,2)],verify_args=args,proof_bytes=len(proof),conversion_hint_bytes=len(hints)+len(hi)+len(ui),hash_hint_bytes=len(hh)+len(uh),statement=data['statement'],challenges=dict(lambda_key=hex(lam),y=hex(y),z=hex(z),x=hex(x)),limitations=['Finite hash-to-group counter bound64; no rare outer basis collision retry. Honest fixtures reject collision instead of modifying bases.'])
