use traits::{Into, TryInto};
use option::{OptionTrait, OptionSerde};
use result::ResultTrait;
use clone::Clone;
use array::{ArrayTrait, ArrayTCloneImpl, SpanTrait};
use serde::Serde;
use ec::EcPoint;
use starknet::{
    StorageAccess, SyscallResult, SyscallResultTrait,
    storage_access::{
        StorageAddress, StorageBaseAddress, storage_address_from_base,
        storage_address_from_base_and_offset,
    },
    syscalls::{storage_read_syscall, storage_write_syscall}
};

use alexandria::{data_structures::array_ext::ArrayTraitExt, storage::list::{List, ListTrait}};

use super::serde::EcPointSerde;


// We use this wrapper struct so that we can do a blanket implementation of StorageAccess for types that impl Serde.
// If we were to do a blanket implementation directly on types that impl Serde, we'd have conflicting
// StorageAccess implementations for some types.
#[derive(Drop)]
struct StorageAccessSerdeWrapper<T> {
    inner: List<felt252>, 
}

// Would love to #[derive(storage_access::StorageAccess)] on `StorageAccessSerdeWrapper<T>`,
// but the compiler doesn't properly derive the `StorageAccess` trait for generic types.
// So, we manually call out to the `StorageAccess` impl of the underlying `List` type.
impl WrapperStorageAccessImpl<T> of StorageAccess<StorageAccessSerdeWrapper<T>> {
    fn read(
        address_domain: u32, base: StorageBaseAddress
    ) -> SyscallResult<StorageAccessSerdeWrapper<T>> {
        let inner = StorageAccess::<List<felt252>>::read(address_domain, base)?;
        Result::Ok(StorageAccessSerdeWrapper { inner })
    }

    fn write(
        address_domain: u32, base: StorageBaseAddress, value: StorageAccessSerdeWrapper<T>
    ) -> SyscallResult<()> {
        StorageAccess::<List<felt252>>::write(address_domain, base, value.inner)
    }

    fn read_at_offset_internal(
        address_domain: u32, base: StorageBaseAddress, offset: u8
    ) -> SyscallResult<StorageAccessSerdeWrapper<T>> {
        let inner = StorageAccess::<List<felt252>>::read_at_offset_internal(
            address_domain, base, offset
        )?;
        Result::Ok(StorageAccessSerdeWrapper { inner })
    }

    fn write_at_offset_internal(
        address_domain: u32,
        base: StorageBaseAddress,
        offset: u8,
        value: StorageAccessSerdeWrapper<T>
    ) -> SyscallResult<()> {
        StorageAccess::<List<felt252>>::write_at_offset_internal(
            address_domain, base, offset, value.inner
        )
    }

    fn size_internal(value: StorageAccessSerdeWrapper<T>) -> u8 {
        StorageAccess::<List<felt252>>::size_internal(value.inner)
    }
}

#[generate_trait]
impl StorageAccessSerdeImpl<
    T, impl TSerde: Serde<T>, impl TDrop: Drop<T>
> of StorageAccessSerdeTrait<T> {
    /// This "unwraps" the value being stored by reading its serialization from storage & deserializing it.
    fn unwrap(self: StorageAccessSerdeWrapper<T>) -> T {
        let mut serialized_span = self.inner.array().span();
        let inner: T = Serde::deserialize(ref serialized_span).unwrap();
        inner
    }

    /// This "rewraps" the value being stored by overwriting its serialization in storage.
    /// IMPORTANT: THIS ASSUMES THAT `.write` IS CALLED WITH THE `StorageAccessSerdeWrapper` AFTER THIS FUNCTION IS CALLED.
    /// This is because, in the case that the rewrapped value's serialization is shorter than the original value,
    /// the length of the `List` will remain unchanged unless `.write` is called, and thus extra garbage elements will be 
    /// read in from storage on the subsequent call of `unwrap`.
    fn rewrap(mut self: StorageAccessSerdeWrapper<T>, value: T) -> StorageAccessSerdeWrapper<T> {
        let mut serialized = ArrayTrait::new();
        value.serialize(ref serialized);

        let mut list = self.inner;
        let init_len = list.len();
        let ser_len = serialized.len();

        let mut i = 0;
        loop {
            if i == ser_len || i == init_len {
                break;
            };

            let felt = serialized.pop_front().unwrap();
            list.set(i, felt);
            i += 1;
        };

        // If ser_len <= init_len, this loop will immediately break, and as mentioned
        // above, ser_len will be written to storage as the list len regardless.
        // Thus, the previous elements beyond ser_len will be left unchanged, but will never be read.
        // If ser_len > init_len, this loop will append the remaining elements of `serialized`
        // to the list.
        loop {
            if i == ser_len {
                break;
            };

            let felt = serialized.pop_front().unwrap();
            list.append(felt);
            i += 1;
        };

        // We set the length here to ensure that it is correctly updated in the case that the new
        // serialization is shorter than the previous one (this means only `set` was called
        // in the first loop above, which does not update the list length).
        // The assumed subsequent call to `write` will overwrite it with the `.len` field as we set it here.
        // Note that the (potential) calls to `append` above will update the list length properly, meaning the
        // assumed subsequent call to `write` will be redundant.
        // TODO: This is inefficient due to redundant writes of the list len, optimize w/ a forked impl of `List`
        list.len = ser_len;
        self.inner = list;
        self
    }
}
