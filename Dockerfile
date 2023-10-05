FROM lukemathwalker/cargo-chef:latest-rust-1.70-slim-buster AS chef
WORKDIR /app

FROM chef as planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef as builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .

RUN apt-get update && \
    apt-get install -y build-essential wget pkg-config libssl-dev clang libclang-dev lld && \
    rm -rf /var/lib/apt/lists/*

ARG BUILD_TAG
ARG BUILD_TIMESTAMP

ENV BUILD_TAG = ${BUILD_TAG}
ENV BUILD_TIMESTAMP = ${BUILD_TIMESTAMP}
RUN cargo build --release

# Distribute the binary
FROM gcr.io/distroless/cc-debian11 AS release

WORKDIR /dist

COPY --from=builder /app/target/release/sp-security ./sp-security
COPY .env /dist/
CMD ["/dist/sp-security"]