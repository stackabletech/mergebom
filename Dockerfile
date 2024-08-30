
FROM oci.stackable.tech/sdp/ubi9-rust-builder AS builder

FROM scratch
COPY --from=builder /app/mergebom  /