![](img/logo_dark.png)
#

<div>
  <a href="https://twitter.com/renegade_fi" target="_blank">
    <img src="https://img.shields.io/twitter/follow/renegade_fi?style=social" />
  </a>
  <a href="https://discord.gg/renegade-fi" target="_blank">
    <img src="https://img.shields.io/discord/1032770899675463771?label=Join%20Discord&logo=discord&style=social" />
  </a>
</div>

This repository contains the StarkNet smart contract code for Renegade's settlement layer. This includes managing the system-global state, verifying bulletproofs, and emitting events that are consumed by the p2p network.
## Contract Development Setup
We use the following stack to support StarkNet development:
- [`poetry`](https://github.com/python-poetry/poetry): For managing python dependencies and wrapping many `nile` commands.
- [`nile`](https://github.com/OpenZeppelin/nile): For managing the StarkNet development process.
- [`amarna`](https://github.com/crytic/amarna): A static-analyzer and linter for Cairo.
  
To setup your local machine for Renegade contract development:

### Install Poetry
We use `poetry` to streamline dependency management and automate commmon Renegade specific tasks.

Head to the Poetry [installation docs](https://python-poetry.org/docs/#installation) and follow the system-specific instructions there to install poetry. 

Check that the installation was successful by running
```
poetry --version
```

Now, install the project dependencies by running
```
poetry install
```
This should install all the important dependencies for developing on the project. This includes `nile` (Cairo toolchain), amarna (Cairo linter), `pytest` for unit tests.

You can test that the installation happned correctly by running

```
poetry run nile compile
```
This should allocate a virtual environment for the command and compile the contract sources within it.

You can also run the unit tests for the workspace with
```
poetry run pytest
```