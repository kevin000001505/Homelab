# Kubernetes MCP server access

The MCP Hub's Kubernetes MCP server runs on the monitor Guest, outside the
cluster. It reads the cluster as the `mcp-hub-view` ServiceAccount, which is
bound to the built-in `view` ClusterRole. That role is read-only, and it cannot
read Secrets.

Manifest: [`core/k8s-mcp/mcp-hub-view.yaml`](../../core/k8s-mcp/mcp-hub-view.yaml).
It is applied by hand, like everything else under `core/`.

## Apply

```bash
kubectl apply -f core/k8s-mcp/mcp-hub-view.yaml
```

## Check the permissions

```bash
SA=system:serviceaccount:kube-system:mcp-hub-view
kubectl auth can-i list pods -A --as=$SA      # yes
kubectl auth can-i list secrets -A --as=$SA   # no
kubectl auth can-i create pods --as=$SA       # no
kubectl auth can-i list nodes --as=$SA        # no: view has no cluster-scoped rules
```

## Build the kubeconfig for the MCP server

Run this on a machine with admin access. Then copy the file to the monitor
Guest with mode `600`. Do not commit it, because it contains a long-lived token.

```bash
CA=$(kubectl get secret mcp-hub-view-token -n kube-system -o jsonpath='{.data.ca\.crt}')
TOKEN=$(kubectl get secret mcp-hub-view-token -n kube-system -o jsonpath='{.data.token}' | base64 -d)
umask 077; cat > mcp-hub-view.kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: homelab
    cluster:
      server: https://192.168.1.15:6443
      certificate-authority-data: $CA
users:
  - name: mcp-hub-view
    user:
      token: $TOKEN
contexts:
  - name: mcp-hub-view@homelab
    context: {cluster: homelab, user: mcp-hub-view}
current-context: mcp-hub-view@homelab
EOF
```

Set the MCP server's `KUBECONFIG` (or its `--kubeconfig` flag) to this file.

## Rotate or revoke the token

Delete the Secret. This makes the old token invalid immediately. Then apply the
manifest again to get a new token, and rebuild the kubeconfig.

```bash
kubectl delete secret mcp-hub-view-token -n kube-system
kubectl apply -f core/k8s-mcp/mcp-hub-view.yaml
```

To remove all access, delete every object in the manifest:

```bash
kubectl delete -f core/k8s-mcp/mcp-hub-view.yaml
```
