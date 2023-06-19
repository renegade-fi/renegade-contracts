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
        StorageBaseAddress, storage_address_from_base, storage_address_from_base_and_offset,
    },
    syscalls::{storage_read_syscall, storage_write_syscall}
};

use super::{collections::{ArrayTraitExt}, serde::EcPointSerde};


// We use this wrapper struct so that we can do a blanket implementation of StorageAccess for types that impl Serde.
// If we were to do a blanket implementation directly on types that impl Serde, we'd have conflicting
// StorageAccess implementations for some types.
#[derive(Drop)]
struct StorageAccessSerdeWrapper<T> {
    inner: T
}

impl StorageAccessSerdeImpl<T, impl TSerde: Serde<T>> of Serde<StorageAccessSerdeWrapper<T>> {
    fn serialize(self: @StorageAccessSerdeWrapper<T>, ref output: Array<felt252>) {
        let mut inner_output = ArrayTrait::new();
        self.inner.serialize(ref inner_output);
        output.append(inner_output.len().into());
        output.append_all(ref inner_output);
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<StorageAccessSerdeWrapper<T>> {
        serialized.pop_front()?;
        let inner = Serde::<T>::deserialize(ref serialized)?;
        Option::Some(StorageAccessSerdeWrapper { inner })
    }
}

impl StorageSerdeImpl<
    T, impl Tserde: Serde<T>, impl TDrop: Drop<T>
> of StorageAccess<StorageAccessSerdeWrapper<T>> {
    fn read(
        address_domain: u32, base: StorageBaseAddress
    ) -> SyscallResult<StorageAccessSerdeWrapper<T>> {
        StorageSerdeImpl::<T>::read_at_offset_internal(address_domain, base, 0)
    }

    fn read_at_offset_internal(
        address_domain: u32, base: StorageBaseAddress, offset: u8
    ) -> SyscallResult<StorageAccessSerdeWrapper<T>> {
        // Read serialization len, add 1 to account for the len slot
        let num_slots: u8 = storage_read_syscall(address_domain, storage_address_from_base(base))?
            .try_into()
            .expect('Storage - value too large')
            + 1_u8;

        let mut serialized = ArrayTrait::new();
        let mut slots_read: u8 = 0;
        loop {
            if slots_read == num_slots {
                break;
            }

            let address = storage_address_from_base_and_offset(base, offset + slots_read);
            // Unwrapping here for now since you can't return / use `?` in a loop
            let felt = storage_read_syscall(address_domain, address).unwrap_syscall();
            serialized.append(felt);
            slots_read += 1;
        };
        let mut serialized_span = serialized.span();

        // This deserialize expects to pop off the len slot
        match Serde::<StorageAccessSerdeWrapper<T>>::deserialize(ref serialized_span) {
            Option::Some(val) => Result::Ok(val),
            Option::None(_) => {
                let mut data = ArrayTrait::new();
                data.append('Storage - deser failed');
                Result::Err(data)
            },
        }
    }

    fn write(
        address_domain: u32, base: StorageBaseAddress, value: StorageAccessSerdeWrapper<T>
    ) -> SyscallResult<()> {
        StorageSerdeImpl::<T>::write_at_offset_internal(address_domain, base, 0, value)
    }

    fn write_at_offset_internal(
        address_domain: u32,
        base: StorageBaseAddress,
        offset: u8,
        value: StorageAccessSerdeWrapper<T>
    ) -> SyscallResult<()> {
        // Acts as an assertion that serialization len <= 255
        let mut serialized = ArrayTrait::new();
        value.serialize(ref serialized);
        let _len: u8 = (*(@serialized).at(0_usize)).try_into().expect('Storage - value too large');

        let mut slots_written: u8 = 0;
        loop {
            match serialized.pop_front() {
                Option::Some(felt) => {
                    let address = storage_address_from_base_and_offset(
                        base, offset + slots_written
                    );
                    // Unwrapping here for now since you can't return / use `?` in a loop
                    storage_write_syscall(address_domain, address, felt).unwrap_syscall();
                    slots_written += 1;
                },
                Option::None(_) => {
                    break;
                }
            };
        };

        Result::Ok(())
    }

    fn size_internal(value: StorageAccessSerdeWrapper<T>) -> u8 {
        // Acts as an assertion that serialization len <= 255
        let mut serialized = ArrayTrait::new();
        value.serialize(ref serialized);
        (*(@serialized).at(0_usize)).try_into().expect('Storage - value too large')
    }
}
