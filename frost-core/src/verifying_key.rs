use derive_getters::Getters;
use std::fmt::{self, Debug};

#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

use crate::{Challenge, Ciphersuite, Element, Error, Group, Signature, SigningTarget};

#[cfg(feature = "serde")]
use crate::serialization::ElementSerialization;

/// A valid verifying key for Schnorr signatures over a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone, PartialEq, Eq, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(try_from = "ElementSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "ElementSerialization<C>"))]
pub struct VerifyingKey<C>
where
    C: Ciphersuite,
{
    pub(crate) element: Element<C>,
}

impl<C> VerifyingKey<C>
where
    C: Ciphersuite,
{
    /// Create a new VerifyingKey from the given element.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn new(element: <C::Group as Group>::Element) -> Self {
        Self { element }
    }

    /// Return the underlying element.
    pub fn to_element(self) -> <C::Group as Group>::Element {
        self.element
    }

    /// Return the effective verifying key given the specific signing parameters
    /// to be verified against. For most ciphersuites, this simply returns the
    /// same verifying key unchanged.
    pub fn effective_key(self, sig_params: &C::SigningParameters) -> Self {
        VerifyingKey::new(<C>::effective_pubkey_element(&self, sig_params))
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
        sig_params: &C::SigningParameters,
    ) -> Result<(), Error<C>> {
        // Verify check is h * ( - z * B + R  + c * A) == 0
        //                 h * ( z * B - c * A - R) == 0
        //
        // where h is the cofactor
        let R = signature.R;
        let vk = C::effective_pubkey_element(&self, sig_params);

        let zB = C::Group::generator() * signature.z;
        let cA = vk * challenge.0;
        let check = (zB - cA - R) * C::Group::cofactor();

        if check == C::Group::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verify a purported `signature` over `sig_target` made by this verification key.
    pub fn verify(
        &self,
        sig_target: impl Into<SigningTarget<C>>,
        signature: &Signature<C>,
    ) -> Result<(), Error<C>> {
        C::verify_signature(&sig_target.into(), signature, self)
    }

    /// Computes the group public key given the group commitment.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    pub(crate) fn from_commitment(
        commitment: &crate::keys::VerifiableSecretSharingCommitment<C>,
    ) -> Result<VerifyingKey<C>, Error<C>> {
        Ok(VerifyingKey {
            element: commitment
                .coefficients()
                .first()
                .ok_or(Error::IncorrectCommitment)?
                .value(),
        })
    }
}

impl<C> Debug for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VerifyingKey")
            .field(&hex::encode(self.serialize()))
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
        match v.try_into() {
            Ok(bytes) => Self::deserialize(bytes).map_err(|_| "malformed verifying key encoding"),
            Err(_) => Err("malformed verifying key encoding"),
        }
    }
}

#[cfg(feature = "serde")]
impl<C> TryFrom<ElementSerialization<C>> for VerifyingKey<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(value: ElementSerialization<C>) -> Result<Self, Self::Error> {
        Self::deserialize(value.0)
    }
}

#[cfg(feature = "serde")]
impl<C> From<VerifyingKey<C>> for ElementSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: VerifyingKey<C>) -> Self {
        Self(value.serialize())
    }
}
