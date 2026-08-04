#!/usr/bin/env bash
set -euo pipefail

SHARED=/shared
mkdir -p "$SHARED"

echo "[flowlab] using host docker socket..."

kind delete cluster --name flowlab 2>/dev/null || true

echo "[flowlab] creating kind cluster..."
kind create cluster --config /opt/flowlab/kind-config.yaml --wait 120s || true

mkdir -p /root/.kube
kind get kubeconfig --name flowlab --internal > /root/.kube/config

export KUBECONFIG=/root/.kube/config

echo "[flowlab] waiting for API server..."
for i in $(seq 1 60); do
  if kubectl get --raw='/readyz' >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    echo "[flowlab] cluster API not ready"
    exit 1
  fi
done

if ! kubectl -n kube-system get ds cilium >/dev/null 2>&1; then
  echo "[flowlab] installing Cilium..."
  cilium install --set hubble.tls.enabled=false
fi

echo "[flowlab] enabling Hubble..."
cilium hubble enable
cilium status --wait

kubectl -n kube-system patch svc hubble-relay --type=merge -p '{
  "spec": {"type": "NodePort",
           "ports": [{"port": 80, "targetPort": 4245, "nodePort": 30425, "protocol": "TCP"}]}
}'

kubectl create ns flowlab --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f /opt/flowlab/demo-pods.yaml -n flowlab

echo "[flowlab] READY"
touch "$SHARED/READY"

tail -f /dev/null

