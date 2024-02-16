ARG golangbase=1.15

FROM --platform=linux/amd64 polymeshassociation/rust:debian-nightly-2024-02-06 as rustbuild

ENV VERBOSE=1 RUSTFLAGS=-D\ warnings RUSTC_WRAPPER=/usr/local/cargo/bin/sccache

WORKDIR /build
COPY . .
RUN mv confidential_assets /

RUN rustc --version > rust.version
RUN cargo build --release \
	&& mkdir /assets \
	&& cp ./target/release/polymesh-private /assets/polymesh-private \
	&& cp ./target/release/wbuild/polymesh*/*wasm /assets/

FROM --platform=linux/amd64 golang:${golangbase} as gobuild

ADD .docker/src/health-checks/ /opt/health-check/
ADD .docker/src/rotate-keys/ /opt/rotate-keys/

WORKDIR /opt/health-check
RUN ls -a && \
    go build && \
    chmod 0755 /opt/health-check/polymesh-health-check

WORKDIR /opt/rotate-keys
RUN ls -a && \
    go build && \
    chmod 0755 /opt/rotate-keys/polymesh-rotate-keys

FROM debian:stable-slim

COPY --chown=4002:4002 --from=gobuild      /opt/health-check/polymesh-health-check /usr/local/bin/check
COPY --chown=4002:4002 --from=gobuild      /opt/rotate-keys/polymesh-rotate-keys   /usr/local/bin/rotate
COPY --chown=4001:4001 --from=rustbuild /assets/polymesh-private /usr/local/bin/polymesh-private

RUN mkdir /var/lib/polymesh-private && \
    chown 4001:4001 /var/lib/polymesh-private

USER 4001:4001

ENTRYPOINT ["/usr/local/bin/polymesh-private"]
CMD [ "-d", "/var/lib/polymesh-private" ]

HEALTHCHECK \
    --interval=10s \
    --start-period=120s \
    --timeout=5s \
    --retries=6 \
    CMD /usr/local/bin/check liveness
