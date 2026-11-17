FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS backend
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
WORKDIR /build
COPY provenance/gitleaks-v8.30.1-checksums.txt /build/checksums.txt
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* && case "$TARGETARCH" in amd64) asset="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" ;; arm64) asset="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz" ;; *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; esac && curl -fsSLo "$asset" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$asset" && grep "  $asset$" checksums.txt | sha256sum -c - && tar -xzf "$asset" gitleaks && ./gitleaks version | grep -Fx "$GITLEAKS_VERSION"

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.source="https://github.com/nousergon/scannerctl"
WORKDIR /opt/scannerctl
COPY . /tmp/scannerctl-source
RUN python -m pip install --no-cache-dir /tmp/scannerctl-source && rm -rf /tmp/scannerctl-source
COPY --from=backend /build/gitleaks /usr/local/bin/gitleaks
COPY config/baseline.toml /opt/scannerctl/config/baseline.toml
ENV SCANNERCTL_GITLEAKS=/usr/local/bin/gitleaks
ENV SCANNERCTL_CONFIG=/opt/scannerctl/config/baseline.toml
ENTRYPOINT ["scannerctl"]
CMD ["version", "--format", "json"]
