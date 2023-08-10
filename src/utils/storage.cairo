use traits::TryInto;
use option::OptionTrait;
use integer::U32DivRem;
use array::ArrayTrait;
use hash::LegacyHash;
use serde::Serde;
use starknet::{
    StorageAccess, SyscallResult, SyscallResultTrait,
    storage_access::{
        StorageBaseAddress, storage_address_from_base, storage_base_address_from_felt252,
        storage_address_to_felt252,
    },
};


const MAX_STORAGE_SEGMENT_ELEMS: u32 = 256;

// We use this wrapper struct so that we can do a blanket implementation of StorageAccess for types that impl Serde.
// If we were to do a blanket implementation directly on types that impl Serde, we'd have conflicting
// StorageAccess implementations for some types.
#[derive(Drop)]
struct StorageAccessSerdeWrapper<T> {
    inner: T
}

impl WrapperStorageAccessImpl<
    T, impl TSerde: Serde<T>, impl TDrop: Drop<T>
> of StorageAccess<StorageAccessSerdeWrapper<T>> {
    fn read(
        address_domain: u32, base: StorageBaseAddress
    ) -> SyscallResult<StorageAccessSerdeWrapper<T>> {
        let inner = read_inner(address_domain, base, 0);
        Result::Ok(StorageAccessSerdeWrapper { inner })
    }

    fn write(
        address_domain: u32, base: StorageBaseAddress, value: StorageAccessSerdeWrapper<T>
    ) -> SyscallResult<()> {
        write_inner(address_domain, base, 0, value);
        Result::Ok(())
    }

    fn read_at_offset_internal(
        address_domain: u32, base: StorageBaseAddress, offset: u8
    ) -> SyscallResult<StorageAccessSerdeWrapper<T>> {
        let inner = read_inner(address_domain, base, offset);
        Result::Ok(StorageAccessSerdeWrapper { inner })
    }

    fn write_at_offset_internal(
        address_domain: u32,
        base: StorageBaseAddress,
        offset: u8,
        value: StorageAccessSerdeWrapper<T>
    ) -> SyscallResult<()> {
        write_inner(address_domain, base, offset, value);
        Result::Ok(())
    }

    fn size_internal(value: StorageAccessSerdeWrapper<T>) -> u8 {
        // The actual value being stored within the base 256-slot chunk
        // is just the length of the serialization, which takes one slot
        1
    }
}

// Implementation (and documentation) taken from: https://github.com/keep-starknet-strange/alexandria/blob/cairo-v2.0.1/src/storage/list.cairo
// This function finds the StorageBaseAddress of a "storage segment" (a continuous space of 256 storage slots)
// and an offset into that segment where a value at `index` is stored
// each segment can hold up to 256 felts
//
// the way how the address is calculated is very similar to how a LegacyHash map works:
//
// first we take the `list_base` address which is derived from the name of the storage variable
// then we hash it with a `key` which is the number of the segment where the element at `index` belongs (from 0 upwards)
// we hash these two values: H(list_base, key) to the the `segment_base` address
// finally, we calculate the offset into this segment, taking into account the size of the elements held in the array
//
// by way of example:
//
// say we have an List<Foo> and Foo's storage_size is 8
// struct storage: {
//    bar: List<Foo>
// }
//
// the storage layout would look like this:
//
// segment0: [0..31] - elements at indexes 0 to 31
// segment1: [32..63] - elements at indexes 32 to 63
// segment2: [64..95] - elements at indexes 64 to 95
// etc.
//
// where addresses of each segment are:
//
// segment0 = hash(bar.address(), 0)
// segment1 = hash(bar.address(), 1)
// segment2 = hash(bar.address(), 2)
//
// so for getting a Foo at index 90 this function would return address of segment2 and offset of 26
fn calculate_base_and_offset_for_index(
    list_base: StorageBaseAddress, index: u32
) -> (StorageBaseAddress, u8) {
    let (key, offset) = U32DivRem::div_rem(index, MAX_STORAGE_SEGMENT_ELEMS.try_into().unwrap());

    let segment_base = storage_base_address_from_felt252(
        LegacyHash::hash(storage_address_to_felt252(storage_address_from_base(list_base)), key)
    );

    (segment_base, offset.try_into().unwrap())
}

/// This reads in the associated `List<felt252>` from storage, and deserializes the inner value.
fn read_inner<T, impl TSerde: Serde<T>, impl TDrop: Drop<T>>(
    address_domain: u32, base: StorageBaseAddress, offset: u8, 
) -> T {
    let ser_len: u32 = StorageAccess::read_at_offset_internal(address_domain, base, offset)
        .unwrap_syscall();
    let mut serialized: Array<felt252> = ArrayTrait::new();

    let mut i = 0;
    loop {
        if i == ser_len {
            break;
        };

        let (seg_base, seg_offset) = calculate_base_and_offset_for_index(base, i);
        serialized
            .append(
                StorageAccess::read_at_offset_internal(address_domain, seg_base, seg_offset)
                    .unwrap_syscall()
            );

        i += 1;
    };

    let mut serialized_span = serialized.span();
    let inner: T = Serde::deserialize(ref serialized_span).unwrap();
    inner
}

/// This serializes the inner value and writes the serialization to storage.
/// Also writes the serialization length to the base storage segment.
fn write_inner<T, impl TSerde: Serde<T>, impl TDrop: Drop<T>>(
    address_domain: u32, base: StorageBaseAddress, offset: u8, value: StorageAccessSerdeWrapper<T>, 
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
        StorageAccess::write_at_offset_internal(
            address_domain, seg_base, seg_offset, *serialized[i]
        )
            .unwrap_syscall();

        i += 1;
    };

    StorageAccess::write_at_offset_internal(address_domain, base, offset, ser_len);
}
