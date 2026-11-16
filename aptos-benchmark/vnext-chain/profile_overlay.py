"""Read-only localhost proxy exposes exact session state to official profiler.

Only compiled modules, registered benchmark resources, and (when diagnostic)
the execution ceiling are overlaid. Transaction submission is always blocked.
"""
import hashlib,http.server,json,pathlib,re,subprocess,threading,urllib.request,urllib.error
from run_honest import API,CLI,RUNTIME,ADDR,PROFILE,invoke,leb,vec
def uleb(b,p=0):
    n=0;s=0
    while True:
        v=b[p];p+=1;n|=(v&127)<<s
        if v<128:return n,p
        s+=7
def blob(b,p):
    n,p=uleb(b,p);return b[p:p+n],p+n
def structtag(b,p):
    addr=b[p:p+32].hex();p+=32;m,p=blob(b,p);n,p=blob(b,p);count,p=uleb(b,p)
    assert count==0,'No generic benchmark resource expected'
    return f'0x{addr}::{m.decode()}::{n.decode()}',p
def statekey(b,p):
    start=p;variant,p=uleb(b,p)
    if variant==0:
        addr=b[p:p+32].hex();p+=32;path,p=blob(b,p)
        kind,o=uleb(path)
        if kind==0:
            # Code access path serializes ModuleId (address then identifier).
            if len(path)-o>=33:
                a=path[o:o+32].hex();o+=32;m,o=blob(path,o)
            else:a=addr;m,o=blob(path,o)
            key=f'code::0x{a}::{m.decode()}'
        elif kind==1:
            tag,o=structtag(path,o);key=f'resource::0x{addr}::{tag}'
        else:key=None
    elif variant==1:
        handle=b[p:p+32].hex();p+=32;k,p=blob(b,p);key='table_item::0x'+handle+'::'+k.hex()
    elif variant==2:
        _,p=blob(b,p);key=None
    else:raise ValueError(('Unknown StateKey variant',variant,b.hex()))
    return key,b[start:p],p
def normalize(k):
    # Session strings canonicalize 0x1; state keys contain full addresses.
    return re.sub(r'0x([0-9a-fA-F]+)',lambda m:'0x'+m.group(1).lower().zfill(64),k)
def profile(folder,session,module,function,args,env,full,fold=True):
    delta=json.loads((session/'delta.json').read_text());overlays={normalize(k):bytes.fromhex(v)for k,v in delta.items()}
    events=[];snapshot=int(env['snapshot'])
    with urllib.request.urlopen(API,timeout=15)as base:
        ledger_headers={k:v for k,v in base.headers.items()if k.lower().startswith('x-aptos')}
    account=overlays[normalize('resource::0x'+ADDR+'::0x1::account::Account')]
    resource_length,account_pos=uleb(account,1);account_data=account[account_pos:account_pos+resource_length]
    auth_len,sequence_pos=uleb(account_data);sequence_pos+=auth_len
    sequence=int.from_bytes(account_data[sequence_pos:sequence_pos+8],'little')
    params=['vector<u8>']*13 if module=='wtas_vnext' else ['&signer']+['vector<u8>']*4+['u64']
    if module=='wtas_vnext':params[3]='u64'
    if module=='das_reference':params=['&signer','vector<u8>','vector<u8>']
    abi={'address':'0x'+ADDR,'name':module,'friends':[],'exposed_functions':[{'name':function,'visibility':'public','is_entry':True,'is_view':False,'generic_type_params':[],'params':params,'return':[]}],'structs':[]}
    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def do_GET(self):self.forward()
        def do_POST(self):
            if '/transactions'in self.path:self.send_error(405,'Profiler proxy blocks transaction submissions');return
            self.forward()
        def forward(self):
            data=self.rfile.read(int(self.headers.get('Content-Length',0)))if self.command=='POST'else None
            headers={k:v for k,v in self.headers.items()if k.lower()not in ['host','content-length','accept-encoding','connection']}
            event={'method':self.command,'path':self.path,'body_hex':data.hex()if data and 'state_values'in self.path else None,'overlaid':[]}
            try:
                if '/experimental/state_values/raw'in self.path and data:
                    if data[:1]==b'{':
                        requested=json.loads(data);encoded=bytes.fromhex(requested['key'].removeprefix('0x'));key,raw,p=statekey(encoded,0)
                        assert p==len(encoded)
                        lookup=normalize(key)if key else None
                        if lookup in overlays:
                            result=overlays[lookup];event['overlaid'].append(key)
                            self.send_response(200)
                            for k,v in ledger_headers.items():self.send_header(k,v)
                            self.send_header('Content-Type','application/x-bcs');self.send_header('Content-Length',str(len(result)));self.end_headers();self.wfile.write(result);events.append(event);return
                        req=urllib.request.Request('http://127.0.0.1:8080'+self.path,data=data,headers=headers,method='POST')
                        try:r=urllib.request.urlopen(req,timeout=60)
                        except urllib.error.HTTPError as e:r=e
                        body=r.read();self.send_response(r.status)
                        for k,v in r.headers.items():
                            if k.lower()not in ['content-length','transfer-encoding','connection','content-encoding']:self.send_header(k,v)
                        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);event['status']=r.status;events.append(event);return
                    count,p=uleb(data);keys=[]
                    for i in range(count):
                        key,raw,p=statekey(data,p);keys.append((key,raw))
                    assert p==len(data),(p,len(data))
                    result=bytearray(leb(count));response_headers={}
                    for key,raw in keys:
                        lookup=normalize(key)if key else None
                        if lookup in overlays:
                            result+=b'\x01'+overlays[lookup];event['overlaid'].append(key)
                        else:
                            req=urllib.request.Request('http://127.0.0.1:8080'+self.path,data=b'\x01'+raw,headers=headers,method='POST')
                            with urllib.request.urlopen(req,timeout=60)as r:
                                value=r.read();response_headers=dict(r.headers);assert value[:1]==b'\x01';result+=value[1:]
                    self.send_response(200)
                    for k,v in response_headers.items():
                        if k.lower()not in ['content-length','content-type','transfer-encoding','connection','content-encoding']:self.send_header(k,v)
                    self.send_header('Content-Type','application/x-bcs');self.send_header('Content-Length',str(len(result)));self.end_headers();self.wfile.write(result);events.append(event);return
                req=urllib.request.Request('http://127.0.0.1:8080'+self.path,data=data,headers=headers,method=self.command)
                try:r=urllib.request.urlopen(req,timeout=60)
                except urllib.error.HTTPError as e:r=e
                body=r.read();status=r.status;ctype=r.headers.get('Content-Type','')
                if '/module/'+module in self.path:
                    code=overlays[normalize('code::0x'+ADDR+'::'+module)]
                    length,pos=uleb(code,1);actual=code[pos:pos+length]
                    body=json.dumps({'bytecode':'0x'+actual.hex(),'abi':abi}).encode();status=200;ctype='application/json';event['overlaid'].append('module ABI/code')
                elif self.path.split('?')[0].rstrip('/')in ['/v1/accounts/'+ADDR,'/v1/accounts/0x'+ADDR] and 'json'in ctype:
                    value=json.loads(body);value['sequence_number']=str(sequence);body=json.dumps(value).encode();event['overlaid'].append('session sequence number')
                elif self.path.rstrip('/')=='/v1' and 'json'in ctype:
                    node=json.loads(body);node['ledger_version']=str(snapshot);body=json.dumps(node).encode()
                self.send_response(status)
                for k,v in r.headers.items():
                    if k.lower()not in ['content-length','content-type','transfer-encoding','connection','content-encoding']:self.send_header(k,v)
                self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                event['status']=status;events.append(event)
            except Exception as exc:
                event['error']=repr(exc);events.append(event);self.send_error(500,str(exc))
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        cmd=[CLI,'move','run','--profile',PROFILE,'--url',f'http://127.0.0.1:{server.server_port}/v1','--function-id','0x'+ADDR+'::'+module+'::'+function,'--args',*args,'--max-gas','200000','--gas-unit-price','100','--assume-yes','--profile-gas']
        if fold:cmd.append('--fold-unique-stack')
        code,res=invoke(folder,'profile-overlay',cmd)
    finally:
        server.shutdown();server.server_close();(folder/'profile-overlay-requests.json').write_text(json.dumps(events,indent=2))
    assert code==0 and res.get('Result',{}).get('success')is True,(res,'see profile-overlay.log and requests')
    assert res['Result']['gas_used']==full['total_charge_gas_units'],('Profiler/session fee mismatch',res,full)
    log=(folder/'profile-overlay.log').read_text();m=re.search(r'Gas report saved to (.+)\.',log)
    assert m,log
    report=RUNTIME/m.group(1)
    import shutil
    target=folder/'gas-profile';shutil.copytree(report,target,dirs_exist_ok=True)
    (folder/'profile-overlay.json').write_text(json.dumps({'official_profiler':True,'session_delta_overlay':True,'transactions_submitted':False,'full_execution':full['execution_gas_units'],'source_report':str(report)},indent=2))
    return target
