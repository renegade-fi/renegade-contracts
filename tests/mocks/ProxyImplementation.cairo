// SPDX-License-Identifier: MIT
// OpenZeppelin ProxiableImplementation defined here:
// https://github.com/OpenZeppelin/cairo-contracts/blob/main/tests/mocks/ProxiableImplementation.cairo
// with an additional upgrade method for UUPS proxy implementation

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

from openzeppelin.upgrades.library import Proxy

//
// Storage
//

@storage_var
func value() -> (val: felt) {
}

//
// Initializer
//

@external
func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    proxy_admin: felt
) {
    Proxy.initializer(proxy_admin);
    return ();
}

//
// Upgrade
//

@external
func upgrade{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    implementation_hash: felt
) {
    Proxy.assert_only_admin();
    Proxy._set_implementation_hash(implementation_hash);
    return ();
}

//
// Getters
//

@view
func getValue{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (val: felt) {
    return value.read();
}

@view
func getAdmin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (admin: felt) {
    return Proxy.get_admin();
}

//
// Setters
//

@external
func setValue{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(val: felt) {
    value.write(val);
    return ();
}

@external
func setAdmin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(address: felt) {
    Proxy.assert_only_admin();
    Proxy._set_admin(address);
    return ();
}
