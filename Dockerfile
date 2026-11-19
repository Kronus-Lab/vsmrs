FROM rust:1-alpine AS builder
RUN apk add --no-cache build-base musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/vsm /vsm
WORKDIR /app
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/vsm"]
