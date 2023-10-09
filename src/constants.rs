//! Constants that parameterize the Plonk proof system

/// The number of different wire types that can be used in the gates of the circuit.
/// Currently, this value is 3, corresponding to the following wire types:
/// - Left input wires
/// - Right input wires
/// - Output wires
pub const NUM_WIRE_TYPES: usize = 3;

/// The number of selectors used in each gate of the circuit.
/// Currently, this value is 5, corresponding to the following selectors:
/// - `q_L`: The selector for the left input wires
/// - `q_R`: The selector for the right input wires
/// - `q_O`: The selector for the output wires
/// - `q_M`: The selector for the multiplication constraints
/// - `q_C`: The selector for constant constraints
pub const NUM_SELECTORS: usize = 5;
