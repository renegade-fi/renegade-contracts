use renegade_contracts::{verifier::scalar::Scalar, utils::serde::EcPointSerde};

#[starknet::interface]
trait ITranscript<TContractState> {
    fn rangeproof_domain_sep(ref self: TContractState, n: u64, m: u64);
    fn innerproduct_domain_sep(ref self: TContractState, n: u64);
    fn r1cs_domain_sep(ref self: TContractState);
    fn r1cs_1phase_domain_sep(ref self: TContractState);
    fn append_scalar(ref self: TContractState, label: u256, scalar: Scalar);
    fn append_point(ref self: TContractState, label: u256, point: EcPoint);
    fn validate_and_append_point(ref self: TContractState, label: u256, point: EcPoint);
    fn challenge_scalar(ref self: TContractState, label: u256);
    fn get_challenge_scalar(self: @TContractState) -> Scalar;
}

#[starknet::contract]
mod TranscriptWrapper {
    use option::OptionTrait;
    use renegade_contracts::{
        transcript::{Transcript, TranscriptProtocol, TranscriptTrait}, verifier::scalar::Scalar,
        utils::{serde::EcPointSerde, storage::StorageAccessSerdeWrapper}
    };

    #[storage]
    struct Storage {
        transcript: StorageAccessSerdeWrapper<Transcript>,
        challenge_scalar: Option<Scalar>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, label: u256) {
        let transcript = TranscriptTrait::new(label);
        self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
        self.challenge_scalar.write(Option::None(()));
    }

    #[external(v0)]
    impl ITranscriptImpl of super::ITranscript<ContractState> {
        fn rangeproof_domain_sep(ref self: ContractState, n: u64, m: u64) {
            let mut transcript = self.transcript.read().inner;
            transcript.rangeproof_domain_sep(n, m);
            self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
        }

        fn innerproduct_domain_sep(ref self: ContractState, n: u64) {
            let mut transcript = self.transcript.read().inner;
            transcript.innerproduct_domain_sep(n);
            self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
        }

        fn r1cs_domain_sep(ref self: ContractState) {
            let mut transcript = self.transcript.read().inner;
            transcript.r1cs_domain_sep();
            self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
        }

        fn r1cs_1phase_domain_sep(ref self: ContractState) {
            let mut transcript = self.transcript.read().inner;
            transcript.r1cs_1phase_domain_sep();
            self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
        }

        fn append_scalar(ref self: ContractState, label: u256, scalar: Scalar) {
            let mut transcript = self.transcript.read().inner;
            transcript.append_scalar(label, scalar);
            self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
        }

        fn append_point(ref self: ContractState, label: u256, point: EcPoint) {
            let mut transcript = self.transcript.read().inner;
            transcript.append_point(label, point);
            self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
        }

        fn validate_and_append_point(ref self: ContractState, label: u256, point: EcPoint) {
            let mut transcript = self.transcript.read().inner;
            transcript.validate_and_append_point(label, point);
            self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
        }

        fn challenge_scalar(ref self: ContractState, label: u256) {
            let mut transcript = self.transcript.read().inner;
            let challenge_scalar = transcript.challenge_scalar(label);
            self.transcript.write(StorageAccessSerdeWrapper { inner: transcript });
            self.challenge_scalar.write(Option::Some(challenge_scalar));
        }

        fn get_challenge_scalar(self: @ContractState) -> Scalar {
            self.challenge_scalar.read().unwrap()
        }
    }
}
