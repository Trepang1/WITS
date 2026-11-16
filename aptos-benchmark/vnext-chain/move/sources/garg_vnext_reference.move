/// Research arbitrary-domain adaptation of Garg WTS. Native Ristretto group
/// encapsulation, degree-tight batched hidden/clear FRI, Merkle multiproofs.
/// Public preprocessing is registered by the benchmark registry authority.
module bench::garg_vnext_reference {
    use std::vector;
    use std::option;
    use std::signer;
    use std::bcs;
    use std::hash;
    use aptos_std::ristretto255::{Self as r, Scalar, RistrettoPoint};
    use aptos_std::from_bcs;
    use aptos_std::table::{Self, Table};

    struct Parameters has key, drop {
        n: u64, count: u64, threshold: u64, registered_total: u64, registry_digest: vector<u8>, root: vector<u8>,
        xs: vector<vector<u8>>, norms: vector<vector<u8>>, z: vector<vector<u8>>
    }
    struct Upload has key, drop { cells: vector<vector<u8>> }
    struct DomainChunk has store, drop { xs: vector<vector<u8>>, norms: vector<vector<u8>> }
    struct ChunkedDomain has key { chunks: Table<u64, DomainChunk>, count: u64 }
    struct Row has copy, drop { index: u64, cells: vector<vector<u8>> }
    struct Node has drop { index: u64, digest: vector<u8> }

    public entry fun begin(owner: &signer, n: u64, count: u64, threshold: u64, registered_total: u64, registry_digest: vector<u8>, root: vector<u8>, z: vector<vector<u8>>) acquires Parameters {
        assert!(signer::address_of(owner) == @bench, 201);
        assert!(n == 32 || n == 64 || n == 128 || n == 256 || n == 512, 202);
        assert!(count == 96 && threshold > 0 && threshold <= registered_total, 203);
        assert!(vector::length(&root)==32 && vector::length(&registry_digest)==32 && vector::length(&z)==n+1, 204);
        let p = Parameters { n, count, threshold, registered_total, registry_digest, root, xs: vector[], norms: vector[], z };
        if (exists<Parameters>(@bench)) { *borrow_global_mut<Parameters>(@bench)=p; }
        else { move_to(owner,p); };
    }
    public entry fun append_domain(owner: &signer, xs: vector<vector<u8>>, norms: vector<vector<u8>>) acquires Parameters {
        assert!(signer::address_of(owner)==@bench,201);
        assert!(vector::length(&xs)==vector::length(&norms),205);
        let p=borrow_global_mut<Parameters>(@bench);
        vector::append(&mut p.xs,xs); vector::append(&mut p.norms,norms);
        assert!(vector::length(&p.xs)<=32*p.n-32,206);
    }
    public entry fun reset_proof(owner: &signer) acquires Upload {
        let at=signer::address_of(owner);
        if (exists<Upload>(at)) { borrow_global_mut<Upload>(at).cells=vector[]; }
        else { move_to(owner,Upload{cells:vector[]}); };
    }
    /// Storage-only variant: avoid one megabyte-scale public-parameter value.
    /// The verifier and all proof equations are unchanged.
    public entry fun reset_domain_chunks(owner: &signer) acquires ChunkedDomain {
        assert!(signer::address_of(owner)==@bench,201);
        if (exists<ChunkedDomain>(@bench)) {
            let d=borrow_global_mut<ChunkedDomain>(@bench);
            while(d.count>0){d.count=d.count-1;table::remove(&mut d.chunks,d.count);};
        } else {move_to(owner,ChunkedDomain{chunks:table::new(),count:0});};
    }
    public entry fun append_domain_chunk(owner: &signer, xs: vector<vector<u8>>, norms: vector<vector<u8>>) acquires ChunkedDomain {
        assert!(signer::address_of(owner)==@bench,201);
        assert!(vector::length(&xs)==vector::length(&norms) && vector::length(&xs)<=128,205);
        let d=borrow_global_mut<ChunkedDomain>(@bench);
        table::add(&mut d.chunks,d.count,DomainChunk{xs,norms});d.count=d.count+1;
    }
    public entry fun verify_chunked(owner: &signer, apk: vector<u8>, nonce: vector<u8>, sig: vector<u8>, message: vector<u8>, total: u64) acquires Parameters, Upload, ChunkedDomain {
        let p=borrow_global<Parameters>(@bench);let d=borrow_global<ChunkedDomain>(@bench);
        let xs=vector[];let norms=vector[];let i=0;
        while(i < d.count){let c=table::borrow(&d.chunks,i);vector::append(&mut xs,c.xs);vector::append(&mut norms,c.norms);i=i+1;};
        verify_inner(p.n,p.count,p.threshold,p.registered_total,&p.registry_digest,&p.root,&xs,&norms,&p.z,
            &borrow_global<Upload>(signer::address_of(owner)).cells,apk,nonce,sig,message,total);
    }
    public entry fun append_proof(owner: &signer, cells: vector<vector<u8>>) acquires Upload {
        let upload=borrow_global_mut<Upload>(signer::address_of(owner));
        vector::append(&mut upload.cells,cells);
        assert!(vector::length(&upload.cells)<=32768,207);
    }
    public entry fun verify(owner: &signer, apk: vector<u8>, nonce: vector<u8>, sig: vector<u8>, message: vector<u8>, total: u64) acquires Parameters, Upload {
        let p=borrow_global<Parameters>(@bench);
        verify_inner(p.n,p.count,p.threshold,p.registered_total,&p.registry_digest,&p.root,&p.xs,&p.norms,&p.z,
            &borrow_global<Upload>(signer::address_of(owner)).cells,apk,nonce,sig,message,total);
    }
    fun s(b: vector<u8>): Scalar { option::destroy_some(r::new_scalar_from_bytes(b)) }
    fun g(b: vector<u8>): RistrettoPoint { option::destroy_some(r::new_point_from_bytes(b)) }
    fun at(v: &vector<vector<u8>>, i:u64): Scalar { s(*vector::borrow(v,i)) }
    fun add(a:Scalar,b:Scalar):Scalar{r::scalar_add(&a,&b)}
    fun sub(a:Scalar,b:Scalar):Scalar{r::scalar_sub(&a,&b)}
    fun mul(a:Scalar,b:Scalar):Scalar{r::scalar_mul(&a,&b)}
    fun inv(a:Scalar):Scalar{option::destroy_some(r::scalar_invert(&a))}
    fun one():Scalar{r::new_scalar_from_u64(1)}
    fun pow(a:Scalar,n:u64):Scalar{let out=one();while(n>0){if(n%2==1){out=mul(out,a);};a=mul(a,a);n=n/2;};out}
    fun challenge(t:&mut vector<u8>,label:u8):Scalar{vector::push_back(t,label);let a=r::new_scalar_from_sha512(*t);vector::append(t,r::scalar_to_bytes(&a));a}
    fun take(b:&vector<vector<u8>>,pos:&mut u64,count:u64):vector<vector<u8>>{
        let out=vector[];let i=0;while(i < count){let cell=*vector::borrow(b,*pos);assert!(vector::length(&cell)==32,208);vector::push_back(&mut out,cell);*pos=*pos+1;i=i+1;};out
    }
    fun flat(v:&vector<vector<u8>>):vector<u8>{let out=vector[];let i=0;while(i < vector::length(v)){vector::append(&mut out,*vector::borrow(v,i));i=i+1;};out}
    fun leaf(v:&vector<vector<u8>>):vector<u8>{let b=vector[0u8];vector::append(&mut b,flat(v));hash::sha2_256(b)}
    fun node(a:vector<u8>,b:vector<u8>):vector<u8>{let v=vector[1u8];vector::append(&mut v,a);vector::append(&mut v,b);hash::sha2_256(v)}
    // Stable merge sort of query residues: no domain-sized allocation.
    fun select(q:&vector<u64>,size:u64):vector<u64>{
        if(size<=2048) return select_dense(q,size);
        let a=vector[]; let i=0; let len=vector::length(q);
        while(i < len){vector::push_back(&mut a,*vector::borrow(q,i)%(size/2));i=i+1;};
        let width=1;
        while(width < len){
            let out=vector[];let start=0;
            while(start < len){
                let mid=if(start+width < len){start+width}else{len};
                let end=if(start+2*width < len){start+2*width}else{len};
                let l=start;let r=mid;
                while(l < mid || r < end){
                    if(r==end || (l < mid && *vector::borrow(&a,l)<=*vector::borrow(&a,r))){
                        vector::push_back(&mut out,*vector::borrow(&a,l));l=l+1;
                    }else{vector::push_back(&mut out,*vector::borrow(&a,r));r=r+1;};
                };start=end;
            };a=out;width=2*width;
        };
        let indices=vector[];i=0;
        while(i < len){if(i==0 || *vector::borrow(&a,i)!=*vector::borrow(&a,i-1)){vector::push_back(&mut indices,*vector::borrow(&a,i));};i=i+1;};
        let unique=vector::length(&indices);i=0;
        while(i < unique){let v=*vector::borrow(&indices,i)+size/2;vector::push_back(&mut indices,v);i=i+1;};indices
    }
    fun select_dense(q:&vector<u64>,size:u64):vector<u64>{
        let flags=vector[];let i=0;while(i < size){vector::push_back(&mut flags,false);i=i+1;};i=0;
        while(i < vector::length(q)){let a=*vector::borrow(q,i)%(size/2);*vector::borrow_mut(&mut flags,a)=true;*vector::borrow_mut(&mut flags,a+size/2)=true;i=i+1;};
        let indices=vector[];i=0;while(i < size){if(*vector::borrow(&flags,i)){vector::push_back(&mut indices,i);};i=i+1;};indices
    }
    fun row(rows:&vector<Row>,index:u64):&vector<vector<u8>>{
        let lo=0;let hi=vector::length(rows);while(lo < hi){let mid=(lo+hi)/2;let r=vector::borrow(rows,mid);if(r.index < index){lo=mid+1;}else{hi=mid;};};
        let r=vector::borrow(rows,lo);assert!(r.index==index,209);&r.cells
    }
    fun authenticate(proof:&vector<vector<u8>>,pos:&mut u64,root:&vector<u8>,size:u64,indices:&vector<u64>,width:u64):vector<Row>{
        let rows=vector[];let nodes=vector[];let i=0;
        while(i < vector::length(indices)){let index=*vector::borrow(indices,i);let cells=take(proof,pos,width);vector::push_back(&mut nodes,Node{index,digest:leaf(&cells)});vector::push_back(&mut rows,Row{index,cells});i=i+1;};
        while(size>1){let next=vector[];i=0;while(i < vector::length(&nodes)){
            let a=vector::borrow(&nodes,i);let sibling=if(a.index%2==0 && i+1 < vector::length(&nodes) && vector::borrow(&nodes,i+1).index==a.index+1){i=i+1;vector::borrow(&nodes,i).digest}
                else{*vector::borrow(&take(proof,pos,1),0)};
            let digest=if(a.index%2==0){node(a.digest,sibling)}else{node(sibling,a.digest)};
            vector::push_back(&mut next,Node{index:a.index/2,digest});i=i+1;
        };nodes=next;size=size/2;};assert!(vector::length(&nodes)==1 && vector::borrow(&nodes,0).digest==*root,210);rows
    }
    fun batch(row:&vector<vector<u8>>,reg:&vector<vector<u8>>,opened_points:&vector<RistrettoPoint>,opened_scalars:&vector<Scalar>,x:Scalar,at_r:Scalar,coeff:&vector<Scalar>):(RistrettoPoint,Scalar){
        let values=vector[*vector::borrow(reg,0),*vector::borrow(row,1),*vector::borrow(row,2),*vector::borrow(reg,1),*vector::borrow(row,0),*vector::borrow(row,3),*vector::borrow(row,4),*vector::borrow(row,5)];
        let inverse=inv(sub(x,at_r));let x2=mul(x,x);let ps=vector[];let cs=vector[];let fs=r::new_scalar_from_u64(0);let i=0;
        while(i < 8){let shift=if(i==0 || i==3 || i==4){x}else{x2};
            let a=mul(add(*vector::borrow(coeff,2*i),mul(*vector::borrow(coeff,2*i+1),shift)),inverse);
            if(i < 3){let p=g(*vector::borrow(&values,i));let y=vector::borrow(opened_points,i);vector::push_back(&mut ps,r::point_sub(&p,y));vector::push_back(&mut cs,a);}
            else{fs=add(fs,mul(sub(at(&values,i),*vector::borrow(opened_scalars,i-3)),a));};i=i+1;
        };(r::multi_scalar_mul(&ps,&cs),fs)
    }
    fun signature(apk:&vector<u8>,nonce:&vector<u8>,sig:&vector<u8>,message:&vector<u8>){
        let pre=b"Garg/Schnorr/v1";vector::append(&mut pre,*message);vector::append(&mut pre,*nonce);let c=r::new_scalar_from_sha512(pre);
        let ps=vector[g(x"e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"),g(*apk),g(*nonce)];let cs=vector[s(*sig),r::scalar_neg(&c),r::scalar_neg(&one())];
        assert!(r::point_equals(&r::multi_scalar_mul(&ps,&cs),&r::point_identity()),211);
    }
    fun authorization(opened:&vector<vector<u8>>,apk:&vector<u8>,total:u64,n:u64,at_r:Scalar,z:&vector<vector<u8>>){
        let br=at(opened,4);let zr=r::new_scalar_from_u64(0);let i=vector::length(z);while(i>0){i=i-1;zr=add(mul(zr,at_r),at(z,i));};let top=pow(at_r,n-1);
        let ps=vector[g(*vector::borrow(opened,0)),g(*apk),g(*vector::borrow(opened,1)),g(*vector::borrow(opened,2))];
        let cs=vector[br,r::scalar_neg(&top),r::scalar_neg(&one()),r::scalar_neg(&zr)];assert!(r::point_equals(&r::multi_scalar_mul(&ps,&cs),&r::point_identity()),212);
        assert!(r::scalar_equals(&mul(at(opened,3),br),&add(add(mul(r::new_scalar_from_u64(total),top),at(opened,5)),mul(at(opened,6),zr))),213);
        assert!(r::scalar_equals(&mul(br,sub(one(),br)),&mul(at(opened,7),zr)),214);
    }
    fun fri_round(round:u64,n:u64,size:u64,offset:u64,xs:&vector<vector<u8>>,norms:&vector<vector<u8>>,indices:&vector<u64>,registry:&vector<Row>,initial:&vector<Row>,layers:&vector<vector<Row>>,opened_points:&vector<RistrettoPoint>,opened_scalars:&vector<Scalar>,at_r:Scalar,coeff:&vector<Scalar>,c:Scalar,last:&vector<vector<u8>>){
        let j=0;while(j < vector::length(indices)/2){let index=*vector::borrow(indices,j);let other=index+size/2;
            let (g0,f0)=if(round==0){batch(&vector::borrow(initial,j).cells,&vector::borrow(registry,j).cells,opened_points,opened_scalars,at(xs,offset+index),at_r,coeff)}else{let v=&vector::borrow(vector::borrow(layers,round-1),j).cells;(g(*vector::borrow(v,0)),at(v,1))};
            let (g1,f1)=if(round==0){batch(&vector::borrow(initial,j+vector::length(indices)/2).cells,&vector::borrow(registry,j+vector::length(indices)/2).cells,opened_points,opened_scalars,at(xs,offset+other),at_r,coeff)}else{let v=&vector::borrow(vector::borrow(layers,round-1),j+vector::length(indices)/2).cells;(g(*vector::borrow(v,0)),at(v,1))};
            let x0=at(xs,offset+index);let x1=at(xs,offset+other);let inverse=inv(sub(x0,x1));
            let a=mul(mul(sub(c,x1),inverse),at(norms,offset+index));let b=mul(mul(sub(x0,c),inverse),at(norms,offset+other));
            let expected=if(n==2){last}else{row(vector::borrow(layers,round),index)};
            let gp=r::multi_scalar_mul(&vector[g0,g1],&vector[a,b]);let fp=add(mul(f0,a),mul(f1,b));
            assert!(r::point_equals(&gp,&g(*vector::borrow(expected,0))) && r::scalar_equals(&fp,&at(expected,1)),215);j=j+1;
        };
    }
    public fun verify_inner(n:u64,count:u64,threshold:u64,registered_total:u64,digest:&vector<u8>,root:&vector<u8>,xs:&vector<vector<u8>>,norms:&vector<vector<u8>>,z:&vector<vector<u8>>,proof:&vector<vector<u8>>,apk:vector<u8>,nonce:vector<u8>,sig:vector<u8>,message:vector<u8>,total:u64){
        assert!(total>=threshold && total<=registered_total,216);assert!(vector::length(xs)==32*n-32 && vector::length(norms)==32*n-32,217);
        signature(&apk,&nonce,&sig,&message);
        let t=b"Garg/arbitrary-domain/research/v1";
        vector::append(&mut t,bcs::to_bytes(&n));vector::append(&mut t,bcs::to_bytes(&(16*n)));vector::append(&mut t,bcs::to_bytes(&count));vector::append(&mut t,bcs::to_bytes(&threshold));vector::append(&mut t,bcs::to_bytes(&total));
        vector::append(&mut t,*digest);vector::append(&mut t,*root);vector::append(&mut t,copy apk);vector::append(&mut t,copy nonce);vector::append(&mut t,copy sig);vector::append(&mut t,bcs::to_bytes(&vector::length(&message)));vector::append(&mut t,message);
        let pos=0;let initial_root=*vector::borrow(&take(proof,&mut pos,1),0);vector::append(&mut t,copy initial_root);let at_r=challenge(&mut t,1);
        // A challenge colliding with a queried domain point aborts at inversion.
        // Honest fixtures check no collision (probability at most |D|/|F|).
        // Avoid a linear scan of every public domain point in the verifier.
        let opened=take(proof,&mut pos,8);vector::append(&mut t,flat(&opened));let coeff=vector[];let i=0;while(i < 16){vector::push_back(&mut coeff,challenge(&mut t,3));i=i+1;};
        authorization(&opened,&apk,total,n,at_r,z);
        let opened_points=vector[g(*vector::borrow(&opened,0)),g(*vector::borrow(&opened,1)),g(*vector::borrow(&opened,2))];
        let opened_scalars=vector[at(&opened,3),at(&opened,4),at(&opened,5),at(&opened,6),at(&opened,7)];
        let roots=vector[];let challenges=vector[];let rounds=0;let degree=n;
        while(degree>1){vector::push_back(&mut challenges,challenge(&mut t,4));degree=degree/2;rounds=rounds+1;if(degree>1){let rt=*vector::borrow(&take(proof,&mut pos,1),0);vector::append(&mut t,copy rt);vector::push_back(&mut roots,rt);};};
        let last=take(proof,&mut pos,2);vector::append(&mut t,flat(&last));let queries=vector[];i=0;while(i < count){let v=copy t;vector::push_back(&mut v,254);vector::append(&mut v,bcs::to_bytes(&i));let h=hash::sha2_256(v);let low=vector::slice(&h,0,8);vector::push_back(&mut queries,from_bcs::to_u64(low)%(16*n));i=i+1;};
        let indices=select(&queries,16*n);let registry=authenticate(proof,&mut pos,root,16*n,&indices,2);let initial=authenticate(proof,&mut pos,&initial_root,16*n,&indices,6);
        let selections=vector[copy indices];let layers=vector[];i=0;let size=8*n;while(i < rounds-1){let selected=select(&queries,size);vector::push_back(&mut layers,authenticate(proof,&mut pos,vector::borrow(&roots,i),size,&selected,2));vector::push_back(&mut selections,selected);size=size/2;i=i+1;};assert!(pos==vector::length(proof),218);
        i=0;size=16*n;let degree=n;let offset=0;while(i < rounds){fri_round(i,degree,size,offset,xs,norms,vector::borrow(&selections,i),&registry,&initial,&layers,&opened_points,&opened_scalars,at_r,&coeff,*vector::borrow(&challenges,i),&last);offset=offset+size;size=size/2;degree=degree/2;i=i+1;};
    }

}
