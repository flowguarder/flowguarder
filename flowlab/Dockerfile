FROM docker:28-cli

RUN apk add --no-cache bash curl kubectl

ARG KIND_VERSION=v0.27.0
RUN curl -Lo /usr/local/bin/kind \
      "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
    && chmod +x /usr/local/bin/kind

RUN CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt) \
    && ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && curl -L --fail --remote-name-all \
       "https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${ARCH}.tar.gz{,.sha256sum}" \
    && sha256sum -c "cilium-linux-${ARCH}.tar.gz.sha256sum" \
    && tar -xzf "cilium-linux-${ARCH}.tar.gz" -C /usr/local/bin \
    && rm -f cilium-linux-${ARCH}.tar.gz*

RUN HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt) \
    && ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && curl -L --fail --remote-name-all \
       "https://github.com/cilium/hubble/releases/download/${HUBBLE_VERSION}/hubble-linux-${ARCH}.tar.gz{,.sha256sum}" \
    && sha256sum -c "hubble-linux-${ARCH}.tar.gz.sha256sum" \
    && tar -xzf "hubble-linux-${ARCH}.tar.gz" -C /usr/local/bin \
    && rm -f hubble-linux-${ARCH}.tar.gz*

COPY kind-config.yaml /opt/flowlab/kind-config.yaml
COPY demo-pods.yaml   /opt/flowlab/demo-pods.yaml
COPY entrypoint.sh    /usr/local/bin/flowlab-entrypoint.sh
RUN chmod +x /usr/local/bin/flowlab-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/flowlab-entrypoint.sh"]

