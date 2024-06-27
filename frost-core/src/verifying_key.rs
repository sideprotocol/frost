use core::fmt::{self, Debug};
use derive_getters::Getters;

use alloc::{string::ToString, vec::Vec};

#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

use crate::{serialization::SerializableElement, Challenge, Ciphersuite, Error, Group, Signature};

/// A valid verifying key for Schnorr signatures over a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone, PartialEq, Eq, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct VerifyingKey<C>
where
    C: Ciphersuite,
{
    pub(crate) element: SerializableElement<C>,
}

impl<C> VerifyingKey<C>
where
    C: Ciphersuite,
{
    /// Create a new VerifyingKey from the given element.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn new(element: <C::Group as Group>::Element) -> Self {
        Self {
            element: SerializableElement(element),
        }
    }

    /// Return the underlying element.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn to_element(self) -> <C::Group as Group>::Element {
        self.element.0
    }

    /// Check if VerifyingKey is odd
    pub fn y_is_odd(&self) -> bool {
        <C::Group as Group>::y_is_odd(&self.element)
    }


    /// Deserialize from bytes
    pub fn deserialize(
        bytes: <C::Group as Group>::Serialization,
    ) -> Result<VerifyingKey<C>, Error<C>> {
        <C::Group>::deserialize(&bytes)
            .map(|element| VerifyingKey { element })
            .map_err(|e| e.into())
    }

    /// Serialize `VerifyingKey` to bytes
    pub fn serialize(&self) -> <C::Group as Group>::Serialization {
        <C::Group>::serialize(&self.element)
    }

    /// Verify a purported `signature` with a pre-hashed [`Challenge`] made by this verification
    /// key.
    pub(crate) fn verify_prehashed(
        &self,
        challenge: Challenge<C>,
        signature: &Signature<C>,
    ) -> Result<(), Error<C>> {
        // Verify check is h * ( - z * B + R  + c * A) == 0
        //                 h * ( z * B - c * A - R) == 0
        //
        // where h is the cofactor
        let mut R = signature.R;
        let mut vk = self.element;
        if <C>::is_need_tweaking() {
            R = <C>::tweaked_R(&signature.R);
            vk = <C>::tweaked_public_key(&self.element);
        }
        let zB = C::Group::generator() * signature.z;
        let cA = vk * challenge.0;
        let check = (zB - cA - R) * C::Group::cofactor();

        if check == C::Group::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verify a purported `signature` over `msg` made by this verification key.
    pub fn verify(&self, msg: &[u8], signature: &Signature<C>) -> Result<(), Error<C>> {
        C::verify_signature(msg, signature, self)
    }

    /// Computes the group public key given the group commitment.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    pub(crate) fn from_commitment(
        commitment: &crate::keys::VerifiableSecretSharingCommitment<C>,
    ) -> Result<VerifyingKey<C>, Error<C>> {
        Ok(VerifyingKey::new(
            commitment
                .coefficients()
                .first()
                .ok_or(Error::IncorrectCommitment)?
                .value(),
        ))
    }
}

impl<C> Debug for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VerifyingKey")
            .field(
                &self
                    .serialize()
                    .map(hex::encode)
                    .unwrap_or("<invalid>".to_string()),
            )
            .finish()
    }
}

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for VerifyingKey<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        Self::deserialize(&v).map_err(|_| "malformed verifying key encoding")
    }
}
