%lang starknet

// Import all dependencies from the Proxy template, this will automatically allocate
// the external methods in the local contract
from openzeppelin.upgrades.presets.Proxy import constructor, __default__, __l1_default__
