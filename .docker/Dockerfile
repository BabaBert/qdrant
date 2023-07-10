
ARG RUST_VERSION

FROM rust:${RUST_VERSION:-1}-bullseye

RUN apt-get update && \
    apt-get install -y ca-certificates tzdata\
    clang lld cmake protobuf-compiler jq 

RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg

RUN echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

RUN rustup toolchain install nightly && \
    rustup component add rustfmt --toolchain nightly

EXPOSE 6333
EXPOSE 6334
