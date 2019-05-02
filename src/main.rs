//! Joux's one-round tripartite key-exchange using the pairing fiendly curve
//! BLS12-381.
//!
//! References:
//!
//! 1. ["Pairing Implementation Revisited"](https://eprint.iacr.org/2019/077.pdf)
//! 2. ["Implementing Pairings at the 192-bit Security Level"](https://eprint.iacr.org/2012/232.pdf)
//! 3. ["Constructing Elliptic Curves with Prescribed Embedding Degrees"](https://eprint.iacr.org/2002/088.pdf)
//! 4. ["An Introduction to Pairing-Based Cryptography"](https://www.math.uwaterloo.ca/~ajmeneze/publications/pairings.pdf)
//! 5. ["A one round protocol for tripartite Diffie-Hellman"](http://cgi.di.uoa.gr/~aggelos/crypto/page4/assets/joux-tripartite.pdf)

use pairing::{CurveAffine, CurveProjective, Field, PrimeField};
use pairing::bls12_381::{
    G1Affine as G1Elem,
    G2Affine as G2Elem,
    Fq12 as GtElem,
    Fr as ScalarFieldElem,
};
use rand::{thread_rng, Rng, ThreadRng};

#[derive(Debug)]
struct Party {
    sk: ScalarFieldElem,
    pk_g1: G1Elem,
    pk_g2: G2Elem,
    shared_secret: Option<GtElem>,
}

impl Party {
    fn new(rng: &mut ThreadRng) -> Self {
        let sk: ScalarFieldElem = rng.gen();
        let pk_g1 = G1Elem::one().mul(sk.clone()).into_affine();
        let pk_g2 = G2Elem::one().mul(sk.clone()).into_affine();
        Party {
            sk,
            pk_g1,
            pk_g2,
            shared_secret: None,
        }
    }

    fn pk_g1(&self) -> &G1Elem {
        &self.pk_g1
    }

    fn pk_g2(&self) -> &G2Elem {
        &self.pk_g2
    }

    fn shared_secret(&self) -> &GtElem {
        self.shared_secret.as_ref().unwrap()
    }

    fn create_shared_secret(&mut self, party1_pk: &G1Elem, party2_pk: &G2Elem) {
        let sk = self.sk.into_repr();
        let shared_secret = party1_pk.pairing_with(party2_pk).pow(sk);
        self.shared_secret = Some(shared_secret);
    }
}

type Alice = Party;
type Bob = Party;
type Clara = Party;

fn main() {
    let mut rng = thread_rng();

    let mut alice = Alice::new(&mut rng);
    let mut bob = Bob::new(&mut rng);
    let mut clara = Clara::new(&mut rng);

    alice.create_shared_secret(bob.pk_g1(), clara.pk_g2());
    bob.create_shared_secret(clara.pk_g1(), alice.pk_g2());
    clara.create_shared_secret(alice.pk_g1(), bob.pk_g2());

    debug_assert!(
        alice.shared_secret() == bob.shared_secret(),
        "Alice and Bob's shared secret differ"
    );

    debug_assert!(
        alice.shared_secret() == clara.shared_secret(),
        "Alice and Clara's shared secret differ"
    );
}
