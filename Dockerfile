
FROM oci.stackable.tech/sdp/ubi9-rust-builder AS builder

FROM registry.access.redhat.com/ubi9/ubi-minimal AS operator

ARG VERSION
ARG RELEASE="1"

# Update image
RUN microdnf update -y --setopt=install_weak_deps=0 \
    && microdnf clean all \
    && rm -rf /var/cache/yum

COPY --from=builder /app/mergebom  /

ENTRYPOINT ["/mergebom"]
