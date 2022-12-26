%lang starknet

from openzeppelin.account.presets.Account import (
    constructor,
    getPublicKey,
    supportsInterface,
    setPublicKey,
    isValidSignature,
    __validate__,
    __validate_declare__,
    __validate_deploy__,
    __execute__,
)