/// Exact current-vNext authorization relation with checked Edwards/Ristretto
/// encoding, standard Ed25519 signature equations, and combiner authentication.
module bench::wtas_vnext {
    use std::vector;
    use std::option;
    use std::signer;
    use std::bcs;
    use aptos_std::ed25519;
    use aptos_std::aptos_hash as hash;
    use aptos_std::from_bcs;
    use aptos_std::ristretto255::{Self as r, Scalar, RistrettoPoint};
    use bench::vnext_adapter as adapter;

    struct Registry has key, drop {
        n: u64, threshold: u64, total: u64, combiner: vector<u8>,
        weights: vector<u64>, ed: vector<vector<u8>>, images: vector<vector<u8>>,
        digest_input: vector<u8>, digest: vector<u8>
    }
    fun point(b: vector<u8>): RistrettoPoint { option::destroy_some(r::new_point_from_bytes(b)) }
    fun scalar(b: &vector<u8>, pos: u64): Scalar { option::destroy_some(r::new_scalar_from_bytes(adapter::slice(b,pos,32))) }
    fun put(t: &mut vector<u8>, label: vector<u8>, value: vector<u8>) {
        vector::append(t,bcs::to_bytes(&(vector::length(&label) as u32)));
        vector::append(t,label);vector::append(t,bcs::to_bytes(&vector::length(&value)));vector::append(t,value);
    }
    fun challenge(t: &mut vector<u8>, label: vector<u8>): Scalar {
        let counter=0;
        loop {
            let pre=*t;put(&mut pre,b"challenge-label",copy label);put(&mut pre,b"counter",bcs::to_bytes(&counter));
            let d=hash::sha2_512(pre);let b=adapter::slice(&d,0,32);
            *vector::borrow_mut(&mut b,31)=*vector::borrow(&b,31)&31;
            let maybe=r::new_scalar_from_bytes(copy b);
            if(option::is_some(&maybe)) { let s=option::destroy_some(maybe);if(!r::scalar_is_zero(&s)){put(t,label,b);return s}; };
            counter=counter+1;
        }
    }
    fun verify_ed(pk: vector<u8>, sig: vector<u8>, msg: vector<u8>) {
        let p=ed25519::new_unvalidated_public_key_from_bytes(pk);
        let s=ed25519::new_signature_from_bytes(sig);
        assert!(ed25519::signature_verify_strict(&s,&p,msg),101);
    }
    public entry fun begin(owner:&signer,n:u64,threshold:u64,combiner:vector<u8>,hint:vector<u8>) acquires Registry {
        assert!(signer::address_of(owner)==@bench,102);
        assert!((n==32 || n==64 || n==128 || n==256 || n==512) && threshold>0,103);
        assert!(adapter::convert(&combiner,&hint)!=bcs::to_bytes(&0u256),104);
        let reg=Registry{n,threshold,total:0,combiner,weights:vector[],ed:vector[],images:vector[],digest_input:vector[],digest:vector[]};
        if(exists<Registry>(@bench)){*borrow_global_mut<Registry>(@bench)=reg}else{move_to(owner,reg)};
    }
    fun read64(b:&vector<u8>,pos:&mut u64):u64 {
        let v=from_bcs::to_u64(adapter::slice(b,*pos,8));*pos=*pos+8;v
    }
    fun framed(b:&vector<u8>,pos:&mut u64):vector<u8> {let len=read64(b,pos);let out=adapter::slice(b,*pos,len);*pos=*pos+len;out}
    fun decimal(i:u64):vector<u8>{if(i==0)return b"0";let d=vector[];while(i>0){vector::push_back(&mut d,((i%10)as u8)+48);i=i/10;};vector::reverse(&mut d);d}
    fun push(ps:&mut vector<RistrettoPoint>,ss:&mut vector<Scalar>,p:&RistrettoPoint,s:Scalar){vector::push_back(ps,r::point_clone(p));vector::push_back(ss,s)}
    fun zero_msm(ps:&vector<RistrettoPoint>,ss:&vector<Scalar>){assert!(r::point_equals(&r::multi_scalar_mul(ps,ss),&r::point_identity()),108)}
    fun assert_basis_distinct(reg:&Registry,ed:&vector<u8>){
        assert!(*ed!=x"5866666666666666666666666666666666666666666666666666666666666666",120);
        let i=0;while(i < vector::length(&reg.ed)){if(i%3!=0){assert!(*ed!=*vector::borrow(&reg.ed,i),121)};i=i+1;};
    }
    public entry fun append(owner:&signer,data:vector<u8>) acquires Registry {
        assert!(signer::address_of(owner)==@bench,105);let reg=borrow_global_mut<Registry>(@bench);let pos=0;
        while(pos < vector::length(&data)){
            let i=vector::length(&reg.weights);assert!(i < reg.n,106);
            let w=read64(&data,&mut pos);assert!(w>0,107);
            let pk=framed(&data,&mut pos);let hint=framed(&data,&mut pos);let image=adapter::convert(&pk,&hint);
            assert!(image!=bcs::to_bytes(&0u256),109);
            let dp=framed(&data,&mut pos);let dh=framed(&data,&mut pos);let response=framed(&data,&mut pos);
            let di=adapter::convert(&dp,&dh);let t=vector[];
            put(&mut t,b"domain",b"WTAS/PoP/1");put(&mut t,b"i",bcs::to_bytes(&i));put(&mut t,b"pk",copy pk);put(&mut t,b"w",bcs::to_bytes(&w));put(&mut t,b"D",dp);
            let e=challenge(&mut t,b"e");
            zero_msm(&vector[r::basepoint(),point(di),point(copy image)],&vector[scalar(&response,0),r::scalar_neg(&r::scalar_one()),r::scalar_neg(&e)]);
            vector::append(&mut reg.digest_input,copy pk);vector::append(&mut reg.digest_input,bcs::to_bytes(&w));
            vector::push_back(&mut reg.ed,pk);vector::push_back(&mut reg.images,image);
            let j=0;while(j < 2){
                let ed=framed(&data,&mut pos);let ih=framed(&data,&mut pos);let hh=framed(&data,&mut pos);
                let label=if(j==0)b"g/"else b"h/";vector::append(&mut label,decimal(i));
                let image=adapter::hash_group(label,&hh,&ed,&ih);assert_basis_distinct(reg,&ed);
                vector::append(&mut reg.digest_input,copy ed);vector::push_back(&mut reg.ed,ed);vector::push_back(&mut reg.images,image);j=j+1;
            };
            vector::push_back(&mut reg.weights,w);reg.total=reg.total+w;
        };
        if(vector::length(&reg.weights)==reg.n){let d=hash::sha2_512(reg.digest_input);reg.digest=adapter::slice(&d,0,32);assert!(reg.threshold<=reg.total,122)};
    }
    fun statement_and_signatures(reg:&Registry,k:&vector<u8>,sig:&vector<u8>,message:&vector<u8>,total:u64,proof:&vector<u8>,cg:vector<u8>):vector<u8>{
        verify_ed(*k,*sig,*message);
        let t=vector[];
        put(&mut t,b"protocol",b"WTAS/CPU/current-vNext/1");put(&mut t,b"parameter-id",b"Edwards25519-SHA512-253bit-rejection/1");
        put(&mut t,b"registry-digest",reg.digest);put(&mut t,b"registry-version",bcs::to_bytes(&1u64));put(&mut t,b"N",bcs::to_bytes(&reg.n));
        put(&mut t,b"m",*message);put(&mut t,b"R",adapter::slice(sig,0,32));put(&mut t,b"signature-scalar",adapter::slice(sig,32,32));
        put(&mut t,b"K",*k);put(&mut t,b"threshold",bcs::to_bytes(&reg.threshold));put(&mut t,b"selected-weight",bcs::to_bytes(&total));
        let auth=copy t;vector::append(&mut auth,*proof);verify_ed(reg.combiner,cg,auth);t
    }
    fun proof_decoding(k:&vector<u8>,sig:&vector<u8>,proof:&vector<u8>,hints:&vector<u8>,rounds:u64):(RistrettoPoint,vector<RistrettoPoint>){
        let kp=point(adapter::convert(k,&adapter::slice(hints,0,128)));assert!(!r::point_equals(&kp,&r::point_identity()),113);
        adapter::convert(&adapter::slice(sig,0,32),&adapter::slice(hints,128,128));
        let pp=vector[];let j=0;while(j < 4+2*rounds){let offset=if(j < 4)32*j else 224+32*(j-4);
            vector::push_back(&mut pp,point(adapter::convert(&adapter::slice(proof,offset,32),&adapter::slice(hints,128*(j+2),128))));j=j+1;};(kp,pp)
    }
    fun transcript_challenges(reg:&Registry,stmt:vector<u8>,proof:&vector<u8>,hh:&vector<u8>,he:&vector<u8>,hi:&vector<u8>,uh:&vector<u8>,ue:&vector<u8>,ui:&vector<u8>):(vector<u8>,RistrettoPoint,RistrettoPoint,Scalar,Scalar,Scalar,Scalar){
        let label=b"WT-Blinding-Generator";vector::append(&mut label,copy stmt);vector::append(&mut label,bcs::to_bytes(&0u64));
        let h=point(adapter::hash_group(label,hh,he,hi));assert_basis_distinct(reg,he);
        let t=vector[];put(&mut t,b"WT-Proof",stmt);put(&mut t,b"H",*he);
        put(&mut t,b"A",adapter::slice(proof,0,32));let lambda=challenge(&mut t,b"lambda_key");
        put(&mut t,b"S",adapter::slice(proof,32,32));let y=challenge(&mut t,b"y");let z=challenge(&mut t,b"z");
        put(&mut t,b"T1",adapter::slice(proof,64,32));put(&mut t,b"T2",adapter::slice(proof,96,32));let x=challenge(&mut t,b"x");
        put(&mut t,b"tau_x",adapter::slice(proof,128,32));put(&mut t,b"mu",adapter::slice(proof,160,32));put(&mut t,b"t_hat",adapter::slice(proof,192,32));
        let label=b"WT-IPA-Generator";vector::append(&mut label,copy t);
        let u=point(adapter::hash_group(label,uh,ue,ui));assert_basis_distinct(reg,ue);assert!(*ue!=*he,123);put(&mut t,b"U",*ue);
        (t,h,u,lambda,y,z,x)
    }
    fun coefficient_generation(t:vector<u8>,proof:&vector<u8>,rounds:u64):(vector<Scalar>,vector<Scalar>){
        let coeff=vector[r::scalar_one()];let lr=vector[];let j=0;
        while(j < rounds){put(&mut t,b"round",bcs::to_bytes(&(j+1)));put(&mut t,b"L",adapter::slice(proof,224+64*j,32));put(&mut t,b"R",adapter::slice(proof,256+64*j,32));
            let c=challenge(&mut t,b"u");let ci=option::destroy_some(r::scalar_invert(&c));let next=vector[];let i=0;
            while(i < vector::length(&coeff)){let a=vector::borrow(&coeff,i);vector::push_back(&mut next,r::scalar_mul(a,&ci));vector::push_back(&mut next,r::scalar_mul(a,&c));i=i+1;};coeff=next;
            vector::push_back(&mut lr,r::scalar_neg(&r::scalar_mul(&c,&c)));vector::push_back(&mut lr,r::scalar_neg(&r::scalar_mul(&ci,&ci)));j=j+1;
        };(coeff,lr)
    }
    fun scalar_and_msm_input(reg:&Registry,proof:&vector<u8>,pp:&vector<RistrettoPoint>,kp:&RistrettoPoint,h:&RistrettoPoint,u:&RistrettoPoint,coeff:&vector<Scalar>,lr:&vector<Scalar>,lambda:Scalar,y:Scalar,z:Scalar,x:Scalar,total:u64):(vector<RistrettoPoint>,vector<Scalar>,vector<RistrettoPoint>,vector<Scalar>){
        let n=reg.n;let rounds=vector::length(lr)/2;
        let tau=scalar(proof,128);let mu=scalar(proof,160);let that=scalar(proof,192);let af=scalar(proof,224+64*rounds);let bf=scalar(proof,256+64*rounds);
        let z2=r::scalar_mul(&z,&z);let yi=option::destroy_some(r::scalar_invert(&y));let yip=r::scalar_one();
        let sum_y=r::scalar_one();let ys=y;let size=n;while(size>1){sum_y=r::scalar_mul(&sum_y,&r::scalar_add(&r::scalar_one(),&ys));ys=r::scalar_mul(&ys,&ys);size=size/2;};
        let ps=vector[];let ss=vector[];let i=0;
        while(i < n){
            let a=r::scalar_add(&r::scalar_mul(&af,vector::borrow(coeff,i)),&z);
            let w=r::new_scalar_from_u64(*vector::borrow(&reg.weights,i));
            let hc=r::scalar_sub(&r::scalar_mul(&r::scalar_sub(&r::scalar_mul(&bf,vector::borrow(coeff,n-1-i)),&r::scalar_mul(&z2,&w)),&yip),&z);
            vector::push_back(&mut ps,point(*vector::borrow(&reg.images,3*i)));vector::push_back(&mut ss,r::scalar_mul(&r::scalar_mul(&lambda,&w),&a));
            vector::push_back(&mut ps,point(*vector::borrow(&reg.images,3*i+1)));vector::push_back(&mut ss,a);
            vector::push_back(&mut ps,point(*vector::borrow(&reg.images,3*i+2)));vector::push_back(&mut ss,hc);
            yip=r::scalar_mul(&yip,&yi);i=i+1;
        };
        i=0;while(i < 2*rounds){push(&mut ps,&mut ss,vector::borrow(pp,4+i),*vector::borrow(lr,i));i=i+1;};
        push(&mut ps,&mut ss,u,r::scalar_sub(&r::scalar_mul(&af,&bf),&that));push(&mut ps,&mut ss,h,mu);
        push(&mut ps,&mut ss,vector::borrow(pp,0),r::scalar_neg(&r::scalar_one()));push(&mut ps,&mut ss,vector::borrow(pp,1),r::scalar_neg(&x));push(&mut ps,&mut ss,kp,r::scalar_neg(&lambda));
        let delta=r::scalar_sub(&r::scalar_mul(&r::scalar_sub(&z,&z2),&sum_y),&r::scalar_mul(&r::scalar_mul(&z2,&z),&r::new_scalar_from_u64(reg.total)));
        let gc=r::scalar_sub(&that,&r::scalar_add(&r::scalar_mul(&z2,&r::new_scalar_from_u64(total)),&delta));
        (ps,ss,vector[r::basepoint(),r::point_clone(h),r::point_clone(vector::borrow(pp,2)),r::point_clone(vector::borrow(pp,3))],vector[gc,tau,r::scalar_neg(&x),r::scalar_neg(&r::scalar_mul(&x,&x))])
    }
    fun polynomial_check(ps:&vector<RistrettoPoint>,ss:&vector<Scalar>){zero_msm(ps,ss)}
    fun ipa_check(ps:&vector<RistrettoPoint>,ss:&vector<Scalar>){zero_msm(ps,ss)}
    public entry fun verify(k:vector<u8>,sig:vector<u8>,message:vector<u8>,total:u64,proof:vector<u8>,hints:vector<u8>,he:vector<u8>,hi:vector<u8>,hh:vector<u8>,ue:vector<u8>,ui:vector<u8>,uh:vector<u8>,cg:vector<u8>) acquires Registry {
        let reg=borrow_global<Registry>(@bench);let n=reg.n;
        assert!(vector::length(&reg.weights)==n && vector::length(&reg.digest)==32 && reg.threshold<=total && total<=reg.total,110);
        let rounds=0;let size=n;while(size>1){rounds=rounds+1;size=size/2;};
        assert!(vector::length(&proof)==32*(9+2*rounds) && vector::length(&hints)==128*(6+2*rounds),111);
        let stmt=statement_and_signatures(reg,&k,&sig,&message,total,&proof,cg);
        let (kp,pp)=proof_decoding(&k,&sig,&proof,&hints,rounds);
        let (t,h,u,lambda,y,z,x)=transcript_challenges(reg,stmt,&proof,&hh,&he,&hi,&uh,&ue,&ui);
        let (coeff,lr)=coefficient_generation(t,&proof,rounds);
        let (ps,ss,poly_p,poly_s)=scalar_and_msm_input(reg,&proof,&pp,&kp,&h,&u,&coeff,&lr,lambda,y,z,x,total);
        polynomial_check(&poly_p,&poly_s);ipa_check(&ps,&ss);
    }
}
