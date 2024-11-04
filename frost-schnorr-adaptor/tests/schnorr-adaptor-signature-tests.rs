use frost_core::Group;
use frost_schnorr_adaptor::*;
use k256::{elliptic_curve::ops::MulByGenerator, ProjectivePoint};
use secp256k1::{schnorr, Secp256k1};
use rand::thread_rng;

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

#[test]
fn check_adaptor_and_schnorr_sign_with_dealer_() {
    let mut rng = thread_rng();

    let msg = [1u8; 32];
    let merkle_root = vec![];

    let adaptor_secret = Secp256K1ScalarField::random(&mut rng);
    let adaptor_point = ProjectivePoint::mul_by_generator(&adaptor_secret);

    let (signing_target, signature, vk) = frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Secp256K1Sha256, _>(
        rng,
        SigningTarget::new(&msg, SigningParameters {
            tapscript_merkle_root: Some(merkle_root),
            adaptor_point: Secp256K1Group::serialize(&adaptor_point).to_vec(),
        }),
    );

    let adapted_signature = adapt(&signature, &adaptor_secret);

    let tweaked_pk = vk.effective_key(signing_target.sig_params()).serialize();
    let mut x_only_tweaked_pk = [0u8; 32];
    x_only_tweaked_pk.copy_from_slice(&tweaked_pk[1..]);

    let secp = Secp256k1::new();
    secp.verify_schnorr(&schnorr::Signature::from_byte_array(adapted_signature.serialize()), signing_target.message(), &secp256k1::XOnlyPublicKey::from_byte_array(&x_only_tweaked_pk).unwrap()).unwrap()
}
