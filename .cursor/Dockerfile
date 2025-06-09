FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV USER=ubuntu
ENV HOME=/home/ubuntu

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    wget \
    unzip \
    jq \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create user and set up home directory
RUN useradd -m -s /bin/bash $USER
USER $USER
WORKDIR $HOME

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="$HOME/.cargo/bin:$PATH"

# Install Node.js via nvm
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
ENV NVM_DIR="$HOME/.nvm"
RUN . $NVM_DIR/nvm.sh && nvm install --lts && nvm use --lts

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    . $HOME/.bashrc && \
    $HOME/.foundry/bin/foundryup
ENV PATH="$HOME/.foundry/bin:$PATH"

# Set default shell
SHELL ["/bin/bash", "-c"]
