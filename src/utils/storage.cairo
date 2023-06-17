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


impl TStorageAccess<
    T, impl TStorageSerde: StorageSerde<T>, impl TDrop: Drop<T>
> of StorageAccess<T> {
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<T> {
        TStorageAccess::<T>::read_at_offset_internal(address_domain, base, 0)
    }

    fn read_at_offset_internal(
        address_domain: u32, base: StorageBaseAddress, offset: u8
    ) -> SyscallResult<T> {
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
        match StorageSerde::<T>::deserialize_storage(ref serialized_span) {
            Option::Some(val) => Result::Ok(val),
            Option::None(_) => {
                let mut data = ArrayTrait::new();
                data.append('Storage - deser failed');
                Result::Err(data)
            },
        }
    }

    fn write(address_domain: u32, base: StorageBaseAddress, value: T) -> SyscallResult<()> {
        TStorageAccess::<T>::write_at_offset_internal(address_domain, base, 0, value)
    }

    fn write_at_offset_internal(
        address_domain: u32, base: StorageBaseAddress, offset: u8, value: T
    ) -> SyscallResult<()> {
        // Acts as an assertion that serialization len <= 255
        let mut serialized = ArrayTrait::new();
        value.serialize_storage(ref serialized);
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

    fn size_internal(value: T) -> u8 {
        // TODO: Kinda sucks to do full serialization for this...
        // should I push a "size" method down to the StorageSerde trait?

        // Acts as an assertion that serialization len <= 255
        let mut serialized = ArrayTrait::new();
        value.serialize_storage(ref serialized);
        (*(@serialized).at(0_usize)).try_into().expect('Storage - value too large')
    }
}

// We use this wrapper trait around Serde (which prepends a length to the serialized data)
// so that we can do a blanket implementation of StorageAccess for types that impl StorageSerde.
// If we were to do a blanket implementation for types that impl Serde, we'd have conflicting
// StorageAccess implementations for some types.
trait StorageSerde<T> {
    fn serialize_storage(self: @T, ref output: Array<felt252>);
    fn deserialize_storage(ref serialized: Span<felt252>) -> Option<T>;
}

fn serialize_storage_generic<T, impl TSerde: Serde<T>>(t: @T, ref output: Array<felt252>) {
    let mut native_output = ArrayTrait::new();
    t.serialize(ref native_output);
    output.append(native_output.len().into());
    output.append_all(ref native_output);
}

fn deserialize_storage_generic<T, impl TSerde: Serde<T>>(
    ref serialized: Span<felt252>
) -> Option<T> {
    serialized.pop_front()?;
    Serde::<T>::deserialize(ref serialized)
}

impl ArrayStorageSerde<T, impl TSerde: Serde<Array<T>>> of StorageSerde<Array<T>> {
    fn serialize_storage(self: @Array<T>, ref output: Array<felt252>) {
        serialize_storage_generic(self, ref output)
    }

    fn deserialize_storage(ref serialized: Span<felt252>) -> Option<Array<T>> {
        deserialize_storage_generic(ref serialized)
    }
}

impl EcPointStorageSerde of StorageSerde<EcPoint> {
    fn serialize_storage(self: @EcPoint, ref output: Array<felt252>) {
        serialize_storage_generic(self, ref output)
    }

    fn deserialize_storage(ref serialized: Span<felt252>) -> Option<EcPoint> {
        deserialize_storage_generic(ref serialized)
    }
}

