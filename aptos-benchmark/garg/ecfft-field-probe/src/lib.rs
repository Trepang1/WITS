//! Checked ECFFT domains for the Garg arbitrary-field research implementation.
use ark_ff::{Field, Fp256, MontBackend, MontConfig, UniformRand, Zero, One};
use ecfft::{ec::{GoodCurve, Point, ShortWeierstrassCurve, Isogeny}, find_curve::find_curve, utils::RationalMap};
use rand::{rngs::StdRng, SeedableRng};

#[derive(MontConfig)]
#[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
#[generator = "2"]
pub struct ScalarFieldConfig;
pub type F = Fp256<MontBackend<ScalarFieldConfig, 4>>;
pub struct Domain { pub layers: Vec<Vec<F>>, pub maps: Vec<RationalMap<F>> }

pub fn domain(n: usize) -> Domain {
    assert!(n.is_power_of_two());
    let mut rng = StdRng::seed_from_u64(20261012);
    let (order_log, mut generator) = find_curve::<F>(&mut rng, n.ilog2());
    for _ in n.ilog2()..order_log { generator += generator; }
    let curve = generator.curve.unwrap();
    let (a,b) = match curve { GoodCurve::Odd {a,b} => (a,b), _ => unreachable!() };
    let shift = a/F::from(3u8);
    let short = ShortWeierstrassCurve::new(b.square()-a*shift, F::from(2u8)*shift*shift*shift-b.square()*shift);
    let leaves = loop {
        let x = F::rand(&mut rng);
        if let Some(y) = (x*(x.square()+a*x+b.square())).sqrt() {
            let mut p = Point::new(x,y,curve);
            let mut xs = vec![];
            for _ in 0..n { xs.push(p.x+shift); p += generator; }
            let mut unique = xs.clone(); unique.sort(); unique.dedup();
            if unique.len() == n { break xs; }
        }
    };
    let mut g = Point::new(generator.x+shift,generator.y,short);
    let mut maps = vec![];
    for remaining in (1..=n.ilog2()).rev() {
        let mut kernel = g;
        for _ in 1..remaining { kernel += kernel; }
        assert!(!kernel.is_zero() && (kernel+kernel).is_zero());
        let d = g.curve.unwrap();
        let x = kernel.x;
        let t = F::from(3u8)*x.square()+d.a;
        let target = ShortWeierstrassCurve::new(d.a-F::from(5u8)*t,d.b-F::from(7u8)*x*t);
        let r = RationalMap::new(&[t,-x,F::one()],&[-x,F::one()]);
        let h = RationalMap::new(&[x.square()-t,-x.double(),F::one()],&[x.square(),-x.double(),F::one()]);
        let iso = Isogeny::new(d,target,r,RationalMap::zero(),h);
        assert!(iso.map(&kernel).is_zero());
        g = iso.map(&g);
        if remaining > 1 {
            assert_eq!(g.y.square(),g.x*g.x*g.x+target.a*g.x+target.b);
            let mut order = g;
            for _ in 1..remaining-1 { order += order; }
            assert!(!order.is_zero() && (order+order).is_zero());
        } else { assert!(g.is_zero()); }
        maps.push(iso.r);
    }
    let mut layers = vec![leaves];
    for map in &maps {
        let previous = layers.last().unwrap();
        let half = previous.len()/2;
        let next: Vec<_> = (0..half).map(|i| {
            let a = map.map(&previous[i]).unwrap();
            assert_eq!(a,map.map(&previous[i+half]).unwrap()); a
        }).collect();
        let mut unique = next.clone(); unique.sort(); unique.dedup();
        assert_eq!(unique.len(),half);
        layers.push(next);
    }
    Domain { layers, maps }
}
