//! Definitions of Solidity interfaces called by contracts in the Renegade protocol

use stylus_sdk::stylus_proc::sol_interface;

sol_interface! {
    interface IVerifier {
        function verify(bytes memory vkey, bytes memory proof, bytes memory public_inputs) external view returns (bool);
    }
}
