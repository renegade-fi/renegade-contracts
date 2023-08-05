//! A simple Fiat-Shamir transcript that uses a Keccak256 hash chain.

use traits::{Into, TryInto};
use option::OptionTrait;
use array::ArrayTrait;
use keccak::keccak_u256s_le_inputs;
use ec::{ec_point_unwrap, ec_point_non_zero, ec_point_is_zero};
use zeroable::IsZeroResult;

use renegade_contracts::{utils::math::hash_to_scalar, verifier::scalar::Scalar};


// TODO: Make a unit test w/ a wrapper contract for this

const TRANSCRIPT_SEED: u256 = 'merlin seed';

#[derive(Drop, Serde)]
struct Transcript {
    /// The current state of the hash chain.
    state: u256,
}

#[generate_trait]
impl TranscriptImpl of TranscriptTrait {
    fn new(label: u256) -> Transcript {
        let mut data = ArrayTrait::new();
        data.append(label);
        let state = keccak_u256s_le_inputs(data.span());
        Transcript { state }
    }

    /// Absorb an arbitrary-length message into the transcript,
    /// hashing it together with the label & the current state.
    fn append_message(ref self: Transcript, label: u256, mut message: Array<u256>) {
        message.append(label);
        message.append(self.state);
        self.state = keccak_u256s_le_inputs(message.span());
    }

    /// Absorb a u64 into the transcript
    fn append_u64(ref self: Transcript, label: u256, x: u64) {
        let mut message = ArrayTrait::new();
        message.append(x.into());
        self.append_message(label, message);
    }

    /// Squeeze a challenge u256 out of the transcript.
    fn challenge_u256(ref self: Transcript, label: u256) -> u256 {
        let mut data = ArrayTrait::new();
        data.append(label);
        data.append(self.state);
        let output = keccak_u256s_le_inputs(data.span());
        self.state = output;

        output
    }
}

#[generate_trait]
impl TranscriptProtocolImpl of TranscriptProtocol {
    /// Append a domain separator for an `n`-bit, `m`-party range proof.
    fn rangeproof_domain_sep(ref self: Transcript, n: u64, m: u64) {
        self.append_dom_sep('rangeproof v1');
        self.append_u64('n', n);
        self.append_u64('m', m);
    }

    /// Append a domain separator for a length-`n` inner product proof.
    fn innerproduct_domain_sep(ref self: Transcript, n: u64) {
        self.append_dom_sep('ipp v1');
        self.append_u64('n', n);
    }

    /// Append a domain separator for a constraint system.
    fn r1cs_domain_sep(ref self: Transcript) {
        self.append_dom_sep('r1cs v1');
    }

    /// Commit a domain separator for a CS without randomized constraints.
    fn r1cs_1phase_domain_sep(ref self: Transcript) {
        self.append_dom_sep('r1cs-1phase');
    }

    /// Append a `scalar` with the given `label`.
    fn append_scalar(ref self: Transcript, label: u256, scalar: Scalar) {
        let mut message = ArrayTrait::new();
        message.append(scalar.into());
        self.append_message(label, message);
    }

    /// Append a `point` with the given `label`.
    fn append_point(ref self: Transcript, label: u256, point: EcPoint) {
        let mut message = ArrayTrait::new();
        match ec_point_is_zero(point) {
            IsZeroResult::Zero(()) => {
                // x
                message.append(0.into());
                // y
                message.append(0.into());
            },
            IsZeroResult::NonZero(p) => {
                let (x, y) = ec_point_unwrap(p);
                message.append(x.into());
                message.append(y.into());
            },
        }
        self.append_message(label, message);
    }

    /// Append a `point` with the given `label`.
    /// Panics if the point is the identity.
    fn validate_and_append_point(ref self: Transcript, label: u256, point: EcPoint) {
        let mut message = ArrayTrait::new();
        let (x, y) = ec_point_unwrap(ec_point_non_zero(point));
        message.append(x.into());
        message.append(y.into());
        self.append_message(label, message);
    }

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(ref self: Transcript, label: u256) -> Scalar {
        hash_to_scalar(self.challenge_u256(label))
    }

    // -----------
    // | HELPERS |
    // -----------

    /// Append a domain separator to the transcript.
    fn append_dom_sep(ref self: Transcript, dom_sep: u256) {
        let mut message = ArrayTrait::new();
        message.append(dom_sep);
        self.append_message('dom-sep', message);
    }
}
