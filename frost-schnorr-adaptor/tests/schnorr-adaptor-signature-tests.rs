use frost_core::Group;
use frost_schnorr_adaptor::{Secp256K1Group, Secp256K1Sha256, SigningParameters, SigningTarget};
use rand::thread_rng;
use serde::Serialize;

#[test]
fn check_add() {

    let mut rng = thread_rng();
    let keypair = k256::SecretKey::random(&mut rng);
    let adaptor_point  = keypair.public_key().to_projective();
    let re = Secp256K1Group::serialize(&adaptor_point);

    let x = Secp256K1Group::deserialize(&re).expect("deseralized failed");
    
    println!("x, {:?}", x);
    println!("ap: {:?}", adaptor_point);
    assert_eq!(x, adaptor_point);
}

#[test]
fn check_adaptor_sign_with_dealer() {
    let rng = thread_rng();
    let key = "eca11793bdd8b042f33013f96e0552c016baeba05d1b8f64d2d1fe929676c03c";
    let priv_key = k256::SecretKey::from_slice(&hex::decode(key).unwrap()).expect("");
    let pubkey_adaptor  = priv_key.public_key().to_projective();
    let adaptor_point = Secp256K1Group::serialize(&pubkey_adaptor);

    let (target, signature, vk) = frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Secp256K1Sha256, _>(
        rng,
        SigningTarget::new(
            [0; 32],
            SigningParameters {
                tapscript_merkle_root: Some([1; 32].to_vec()),
                adaptor_point: adaptor_point.to_vec(),
            },
        ),
    );

    println!("Adaptor Point: {:?}", hex::encode(&target.sig_params().adaptor_point));
    println!("{:?}", signature);
    println!("{:?}", vk);
}