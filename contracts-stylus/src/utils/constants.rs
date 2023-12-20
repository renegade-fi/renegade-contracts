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

/// The serialized VALID COMMITMENTS verification key
#[cfg(feature = "vkeys")]
pub const VALID_COMMITMENTS_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/valid_commitments");

/// The serialized testing VALID COMMITMENTS verification key
#[cfg(feature = "test-vkeys")]
pub const VALID_COMMITMENTS_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/valid_commitments");

/// The serialized VALID REBLIND verification key
#[cfg(feature = "vkeys")]
pub const VALID_REBLIND_VKEY_BYTES: &[u8] = include_bytes!("../../vkeys/prod/valid_reblind");

/// The serialized testing VALID REBLIND verification key
#[cfg(feature = "test-vkeys")]
pub const VALID_REBLIND_VKEY_BYTES: &[u8] = include_bytes!("../../vkeys/test/valid_reblind");

/// The serialized VALID MATCH SETTLE verification key
#[cfg(feature = "vkeys")]
pub const VALID_MATCH_SETTLE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/valid_match_settle");

/// The serialized testing VALID MATCH SETTLE verification key
#[cfg(feature = "test-vkeys")]
pub const VALID_MATCH_SETTLE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/valid_match_settle");

/// The path of values in an empty Merkle tree of height `TEST_MERKLE_HEIGHT`,
/// going from root to leaf
#[cfg_attr(not(feature = "merkle-test-contract"), allow(dead_code))]
pub const TEST_ZEROS: [ScalarField; TEST_MERKLE_HEIGHT] = [
    Fp(
        BigInt([
            6545558527461384500,
            1137270787674609845,
            16413405688133426341,
            2573236809571445843,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            3920910074571912662,
            12263832687740769345,
            2652969935448826190,
            1120873259162845194,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            7317570378139121146,
            8146500231406888520,
            16376727261973886753,
            568890378540217666,
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
            16255992950026435307,
            13572250010926943411,
            11278235144334284075,
            2542990897799067256,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            13668844505100199111,
            7824350475291633769,
            16247131069198100314,
            3048132286879210372,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            12036229008920128863,
            7164329741245094472,
            8471994248626244576,
            1543331933923277697,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            9531744588301560319,
            7116248542529053732,
            18176624840515485227,
            1235710603465431962,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            2762062104638952843,
            13122001106738692628,
            3016272978029331051,
            3134470934056995523,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            4739617987216888967,
            7643492576153501183,
            10028041499328322565,
            338656292053574070,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            1061110609086000690,
            16107075669644069894,
            13245092955417112881,
            3352721414499872609,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            2236782072130304105,
            12981144276753436073,
            12774912581608698296,
            2427894487237908651,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            421943058717979772,
            2593702355809286677,
            16876430172091741333,
            775708722160729233,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            12948820669268411406,
            15497520377164925466,
            11190547690682015575,
            3425111643452366420,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            12013129340623382549,
            6538179279800660390,
            13328188169552447522,
            1912580991096161298,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            10416450289061253107,
            18011872925163666865,
            6091491924401158688,
            948656518994021640,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            7441728408979223475,
            12022072218626728498,
            12933660737100674423,
            1786707790692985605,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            15256147592359136236,
            10161551171692733096,
            12097459217638848257,
            1180796432117517962,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            11697584505978163224,
            10806244280786777540,
            13282198429687596891,
            162704863795503060,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            17374746292684024744,
            7848134429809567156,
            17462349253565163967,
            2011561417478819862,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            8485173435608785369,
            16678838999928349734,
            4570603160740061047,
            3205912194036712912,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            4652992514843821131,
            9626200862060294778,
            1573733935905663339,
            538897265741849678,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            10431622892253023027,
            14514530473768674530,
            10407326227339379097,
            462362593643883720,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            15890981491118767192,
            7720587792545411092,
            3575472510948769249,
            2898706270781364684,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            6715315337192540036,
            15948457395697202743,
            1658074586997567935,
            1261313627286770545,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            601530870724063862,
            16311718439258866740,
            13588776704715097921,
            1130039060129837489,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            1556617422217926206,
            12099518995686580611,
            4982614644568140102,
            1137950917118203363,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            14491411378049748929,
            9244511544643855508,
            12649419278150381160,
            3103597678997428247,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            7486560767983087382,
            9726024122063432914,
            1400359038412901286,
            3039016976130277610,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            12146336101728903577,
            7001576948030374871,
            7527774971134912279,
            1784646815418470434,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            11994296814731248126,
            1160877399311595637,
            18425814232267368767,
            747436689610526396,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            17963632377481573953,
            11150989530393450891,
            5165815624221455941,
            1193574992534091346,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            15111523515181887385,
            12121844053432888828,
            4296901037466108903,
            2863525120518182497,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            6545558527461384500,
            1137270787674609845,
            16413405688133426341,
            2573236809571445843,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            3920910074571912662,
            12263832687740769345,
            2652969935448826190,
            1120873259162845194,
        ]),
        PhantomData,
    ),
    Fp(
        BigInt([
            7317570378139121146,
            8146500231406888520,
            16376727261973886753,
            568890378540217666,
        ]),
        PhantomData,
    ),
];
