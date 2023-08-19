//! We ported the `calculate_base_and_offset_for_index` function and the core read / write functionality (used in `read_inner` and `write_inner`)
//! from Alexandria's `List` type (https://github.com/keep-starknet-strange/alexandria/blob/cairo-v2.0.1/src/storage/list.cairo)
//! rather than instantiating a `List` because our needs don't quite line up to the `ListTrait` interface.
//! We only ever need to read and write an entire array of felts at once, we never need to get-in-place, set-in-place, or append.
//! But these are the functions exposed in `ListTrait`, using a `List` directly would result in a hairy and inefficient implementation on our end
//! (e.g., using `append` will cause redundant writes of the array length to storage).

use traits::TryInto;
use option::OptionTrait;
use integer::U32DivRem;
use array::ArrayTrait;
use hash::LegacyHash;
use serde::Serde;
use starknet::{
    Store, SyscallResult, SyscallResultTrait,
    storage_access::{
        StorageBaseAddress, storage_address_from_base, storage_base_address_from_felt252,
        storage_address_to_felt252,
    },
};


const MAX_STORAGE_SEGMENT_ELEMS: u32 = 256;

// We use this wrapper struct so that we can do a blanket implementation of Store for types that impl Serde.
// If we were to do a blanket implementation directly on types that impl Serde, we'd have conflicting
// Store implementations for some types.
#[derive(Drop)]
struct StoreSerdeWrapper<T> {
    inner: T
}

impl WrapperStoreImpl<
    T, impl TSerde: Serde<T>, impl TDrop: Drop<T>
> of Store<StoreSerdeWrapper<T>> {
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<StoreSerdeWrapper<T>> {
        match read_inner(address_domain, base, 0) {
            Option::Some(inner) => Result::Ok(StoreSerdeWrapper { inner }),
            Option::None(()) => {
                let mut err = ArrayTrait::new();
                err.append('failed to read from storage');
                Result::Err(err)
            }
        }
    }

    fn write(
        address_domain: u32, base: StorageBaseAddress, value: StoreSerdeWrapper<T>
    ) -> SyscallResult<()> {
        write_inner(address_domain, base, 0, value);
        Result::Ok(())
    }

    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, offset: u8
    ) -> SyscallResult<StoreSerdeWrapper<T>> {
        match read_inner(address_domain, base, offset) {
            Option::Some(inner) => Result::Ok(StoreSerdeWrapper { inner }),
            Option::None(()) => {
                let mut err = ArrayTrait::new();
                err.append('failed to read from storage');
                Result::Err(err)
            }
        }
    }

    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, offset: u8, value: StoreSerdeWrapper<T>
    ) -> SyscallResult<()> {
        write_inner(address_domain, base, offset, value);
        Result::Ok(())
    }

    fn size() -> u8 {
        // The actual value being stored within the base 256-slot chunk
        // is just the length of the serialization, which takes one slot
        1
    }
}

/// Implementation (and documentation) adapted from: https://github.com/keep-starknet-strange/alexandria/blob/cairo-v2.0.1/src/storage/list.cairo
/// This function finds the StorageBaseAddress of a "storage segment" (a continuous space of 256 storage slots)
/// and an offset into that segment where a felt at `index` is stored.
///
/// The way the address is calculated is very similar to how a LegacyHash map works:
///
/// First, we take the `list_base` address, which is where the `StoreSerdeWrapper` is rooted in storage
/// (provided in the `Store` trait method arguments).
///
/// Then, we hash it with a `seg_index`, which is the number of the segment where the felt at `index` belongs.
/// We hash these two values: H(list_base, seg_index) to obtain the `segment_base` address.
///
/// Finally, we calculate the offset into this segment.
///
/// As an example:
///
/// Say we have an object which serializes to an array of 1000 felts:
///
/// struct storage: {
///    bar: StoreSerdeWrapper<ObjectOf1000Felts>
/// }
///
/// The storage layout would look like this:
///
/// segment0: [0..255] - felts at indices 0 to 255
/// segment1: [256..511] - felts at indices 256 to 511
/// segment2: [512..767] - felts at indices 512 to 767
/// segment3: [768..1023] - felts at indices 768 to 1023
///
/// Where addresses of each segment are:
///
/// segment0 = hash(bar.address(), 0)
/// segment1 = hash(bar.address(), 1)
/// segment2 = hash(bar.address(), 2)
/// segment3 = hash(bar.address(), 3)
///
/// So getting the 313th felt in the serialization of `bar` would bear segment index 1, and offset 57.
fn calculate_base_and_offset_for_index(
    list_base: StorageBaseAddress, index: u32
) -> (StorageBaseAddress, u8) {
    let (seg_index, seg_offset) = U32DivRem::div_rem(
        index, MAX_STORAGE_SEGMENT_ELEMS.try_into().unwrap()
    );

    let seg_base = storage_base_address_from_felt252(
        LegacyHash::hash(
            storage_address_to_felt252(storage_address_from_base(list_base)), seg_index
        )
    );

    (seg_base, seg_offset.try_into().unwrap())
}

/// This reads in the associated `List<felt252>` from storage, and deserializes the inner value.
fn read_inner<T, impl TSerde: Serde<T>, impl TDrop: Drop<T>>(
    address_domain: u32, base: StorageBaseAddress, offset: u8, 
) -> Option<T> {
    let ser_len: u32 = Store::read_at_offset(address_domain, base, offset).unwrap_syscall();
    let mut serialized: Array<felt252> = ArrayTrait::new();

    let mut i = 0;
    loop {
        if i == ser_len {
            break;
        };

        let (seg_base, seg_offset) = calculate_base_and_offset_for_index(base, i);
        serialized
            .append(Store::read_at_offset(address_domain, seg_base, seg_offset).unwrap_syscall());

        i += 1;
    };

    let mut serialized_span = serialized.span();
    Serde::deserialize(ref serialized_span)
}

/// This serializes the inner value and writes the serialization to storage.
/// Also writes the serialization length to the base storage segment.
fn write_inner<T, impl TSerde: Serde<T>, impl TDrop: Drop<T>>(
    address_domain: u32, base: StorageBaseAddress, offset: u8, value: StoreSerdeWrapper<T>, 
) {
    let mut serialized = ArrayTrait::new();
    value.inner.serialize(ref serialized);

    let ser_len = serialized.len();

    let mut i = 0;
    loop {
        if i == ser_len {
            break;
        };

        let (seg_base, seg_offset) = calculate_base_and_offset_for_index(base, i);
        Store::write_at_offset(address_domain, seg_base, seg_offset, *serialized[i])
            .unwrap_syscall();

        i += 1;
    };

    Store::write_at_offset(address_domain, base, offset, ser_len);
}
