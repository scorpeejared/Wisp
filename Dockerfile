FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler cmake clang libclang-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p wisp-server --bin wisp-relay

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /data
COPY --from=build /src/target/release/wisp-relay /usr/local/bin/wisp-relay
ENV WISP_DB=/data/wisp.db
ENV PORT=8080
EXPOSE 8080
CMD ["wisp-relay"]
