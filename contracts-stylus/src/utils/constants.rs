//! Constants used throughout the contracts

use ark_ff::{BigInt, Fp};
use common::{
    constants::{MERKLE_HEIGHT, TEST_MERKLE_HEIGHT},
    types::ScalarField,
};
use core::marker::PhantomData;

/// The last byte of the `ecAdd` precompile address, 0x06
pub const EC_ADD_ADDRESS_LAST_BYTE: u8 = 6;
/// The last byte of the `ecMul` precompile address, 0x07
pub const EC_MUL_ADDRESS_LAST_BYTE: u8 = 7;
/// The last byte of the `ecPairing` precompile address, 0x08
pub const EC_PAIRING_ADDRESS_LAST_BYTE: u8 = 8;
/// The last byte of the `ecRecover` precompile address, 0x01
pub const EC_RECOVER_ADDRESS_LAST_BYTE: u8 = 1;

/// The index of the last byte of the `ecPairing` precompile result,
/// which is a boolean indicating whether the pairing check succeeded
pub const PAIRING_CHECK_RESULT_LAST_BYTE_INDEX: usize = 31;

/// The byte length of the input to the `ecRecover` precompile
pub const EC_RECOVER_INPUT_LEN: usize = 128;

/// The number of storage slots to use in the Darkpool contract's
/// storage gap, which ensures that there are no storage collisions
/// with the Merkle contract to which it delegatecalls
#[cfg(any(feature = "darkpool", feature = "darkpool-test-contract"))]
pub const STORAGE_GAP_SIZE: usize = 64;

/// The serialized VALID WALLET CREATE verification key
#[cfg(feature = "vkeys")]
pub const VALID_WALLET_CREATE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/valid_wallet_create");

/// The serialized testing VALID WALLET CREATE verification key
#[cfg(feature = "test-vkeys")]
pub const VALID_WALLET_CREATE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/valid_wallet_create");

/// The serialized VALID WALLET UPDATE verification key
#[cfg(feature = "vkeys")]
pub const VALID_WALLET_UPDATE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/valid_wallet_update");

/// The serialized testing VALID WALLET UPDATE verification key
#[cfg(feature = "test-vkeys")]
pub const VALID_WALLET_UPDATE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/valid_wallet_update");

/// The serialized
/// [VALID COMMITMENTS, VALID REBLIND, VALID MATCH SETTLE]
/// verification keys
#[cfg(feature = "vkeys")]
pub const PROCESS_MATCH_SETTLE_VKEYS_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/process_match_settle");

/// The serialized testing
/// [VALID COMMITMENTS, VALID REBLIND, VALID MATCH SETTLE]
/// verification keys
#[cfg(feature = "test-vkeys")]
pub const PROCESS_MATCH_SETTLE_VKEYS_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/process_match_settle");

/// The path of values in an empty Merkle tree of height `TEST_MERKLE_HEIGHT`,
/// going from root to leaf
#[cfg_attr(not(feature = "merkle-test-contract"), allow(dead_code))]
pub const TEST_ZEROS: [ScalarField; TEST_MERKLE_HEIGHT] = [
    Fp(
        BigInt([
            10772295740039794700,
            13748013828842663483,
            6307930248383825682,
            2299690788814741313,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            6562250623858460141,
            10848551954157936743,
            2222027596472178519,
            770658093216651379,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            14542100412480080699,
            1005430062575839833,
            8810205500711505764,
            2121377557688093532,
        ]),
        PhantomData,
    ),
];

/// The path of values in an empty Merkle tree of height `MERKLE_HEIGHT`,
/// going from root to leaf
#[cfg_attr(not(feature = "merkle"), allow(dead_code))]
pub const ZEROS: [ScalarField; MERKLE_HEIGHT] = [
    Fp(
        BigInt([
            7344578010190784131,
            17508866679118096578,
            12688980185972808680,
            2903490608988476222,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            14961687475565586758,
            13593479306388554764,
            2556232457080399949,
            2660788039507648802,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            9723312525113039615,
            18153943088787667540,
            8911946380343182854,
            3046110520954865353,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            7075868627934432491,
            9095164968870528311,
            8271916451775513221,
            2231054541546152259,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            13724767344552159288,
            881032855553829299,
            1641667393102138459,
            92653500913936485,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            16718197177502807540,
            17092579042493284136,
            2775336368083713558,
            3251070739719756010,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            8192955286636285386,
            10085824311326136873,
            4821438135745147941,
            443355933492445218,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            6604285621897967925,
            11772576257125819853,
            18193992999314898250,
            3029733941724304087,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            14121431992158068408,
            6514272721015338071,
            11440800901791879517,
            2113495427121724789,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            16954280684226528616,
            1255270096098409493,
            14801769539334658899,
            986005038699905801,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            18078124503559034440,
            8685634888670926341,
            12163261548960835738,
            2316679783162804459,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            16899172314685359519,
            16224198028834186896,
            10376999186791963298,
            245469684770972214,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            13312377282156507005,
            9005448829656528872,
            15825594130006631757,
            631676509355417760,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            6786832686732018694,
            4409218955972055917,
            15072473682631298930,
            1355754658201528596,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            11801218420497890334,
            16106500026957291403,
            8929261855712017441,
            510087847254171130,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            1965376759016654465,
            1606213939242229909,
            6604222502101971332,
            1162132078247715018,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            9468294168367604566,
            10119718949418709029,
            17645439885592850309,
            150537682432873893,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            2187058261132819693,
            13068280341099950457,
            13372941369883488416,
            1592224683671257566,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            8479713856314761292,
            14782154257529888545,
            10857215690395390695,
            181901385305554574,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            16977485986149375426,
            16538628841972782629,
            6236813005621616080,
            2579884078143837038,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            18336863078452813341,
            4101251495569863736,
            4252450153531979910,
            2529845982011455078,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            13760556351959916425,
            13764458169484165924,
            15279205049118582851,
            1390559705991916239,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            14612776914904100639,
            2096623059520133171,
            14165602610939741341,
            864200906380411747,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            6276377784078832994,
            17305433843839313730,
            2535018843146372113,
            3172676682995291597,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            15220664526588898196,
            10898340875833725770,
            15629905925859069047,
            3195729583951320636,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            13051343795648666528,
            13148479791117912838,
            14553141031527747857,
            831695996703532858,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            2103972342082068345,
            6336836173201018652,
            8853146407765514287,
            1930351865840839525,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            1645331096316424288,
            9853233426618884295,
            15118460804008033289,
            1164714522963820879,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            12145354826561432024,
            15878977179622846493,
            13188942477563288814,
            2357378911117666107,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            10772295740039794700,
            13748013828842663483,
            6307930248383825682,
            2299690788814741313,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            6562250623858460141,
            10848551954157936743,
            2222027596472178519,
            770658093216651379,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            14542100412480080699,
            1005430062575839833,
            8810205500711505764,
            2121377557688093532,
        ]),
        PhantomData,
    ),
];
