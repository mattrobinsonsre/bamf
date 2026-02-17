# BAMF Tiltfile - Local Kubernetes Development
# Run with: tilt up

# Safety: Only allow local Kubernetes contexts. Never deploy to production.
allow_k8s_contexts([
    'rancher-desktop',
    'minikube',
    'docker-desktop',
    'kind-kind',
    'colima',
    'orbstack',
])

# Ensure namespace exists
local('kubectl get ns bamf >/dev/null 2>&1 || kubectl create ns bamf')

# Configuration
config.define_bool("no-volumes")
cfg = config.parse()

# ─────────────────────────────────────────────────────────────────────────────
# Local TLS Certificates (mkcert)
# ─────────────────────────────────────────────────────────────────────────────

local_resource(
    'setup-certificates',
    cmd='''
CERT_DIR="$HOME/.local/share/bamf/certs"
NAMESPACE="bamf"

# Check mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "ERROR: mkcert is not installed. Run: brew install mkcert && mkcert -install"
    exit 1
fi

# Install local CA into system trust store if needed
mkcert -install 2>/dev/null

# Create cert directory
mkdir -p "$CERT_DIR"

# Generate certificates if they don't exist
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    echo "Generating TLS certificates for bamf.local..."
    cd "$CERT_DIR"
    mkcert -cert-file cert.pem -key-file key.pem \\
        "bamf.local" \\
        "*.bamf.local" \\
        "*.tunnel.bamf.local" \\
        "localhost" \\
        "127.0.0.1"
fi

# Create/update Kubernetes TLS secret
echo "Creating/updating bamf-tls-local secret..."
kubectl create secret tls bamf-tls-local \\
    --cert="$CERT_DIR/cert.pem" \\
    --key="$CERT_DIR/key.pem" \\
    --namespace="$NAMESPACE" \\
    --dry-run=client -o yaml | kubectl apply -f -

# Also store mkcert CA cert as a ConfigMap for Traefik to use as default TLS store
# This allows Traefik to serve mkcert-signed certs for IngressRoute resources
CAROOT="$(mkcert -CAROOT)"
if [ -f "$CAROOT/rootCA.pem" ]; then
    kubectl create secret generic bamf-mkcert-ca \\
        --from-file=ca.crt="$CAROOT/rootCA.pem" \\
        --namespace="$NAMESPACE" \\
        --dry-run=client -o yaml | kubectl apply -f -
fi

# Verify /etc/hosts entries
MISSING=""
for HOST in bamf.local; do
    if ! grep -q "$HOST" /etc/hosts; then
        MISSING="$MISSING $HOST"
    fi
done
if [ -n "$MISSING" ]; then
    echo ""
    echo "WARNING: Missing /etc/hosts entries for:$MISSING"
    echo "Run: sudo sh -c 'echo \"127.0.0.1 bamf.local\" >> /etc/hosts'"
    echo ""
fi
''',
    labels=['setup'],
)

# ─────────────────────────────────────────────────────────────────────────────
# Docker Builds
# ─────────────────────────────────────────────────────────────────────────────

# API Server (Python)
# Note: Do NOT set entrypoint here - it would override commands for jobs (migrations, bootstrap)
# The Dockerfile sets the default command; Helm templates override for specific workloads
docker_build(
    'bamf-api',
    context='.',
    dockerfile='docker/Dockerfile.api',
    live_update=[
        sync('./services/bamf', '/app/bamf'),
        run('cd /app && pip install -e .', trigger=['./services/pyproject.toml']),
    ],
)

# Bridge (Go tunnel gateway)
docker_build(
    'bamf-bridge',
    context='.',
    dockerfile='docker/Dockerfile.bridge',
    build_args={
        'VERSION': 'dev',
        'GIT_COMMIT': 'local',
    },
)

# Web UI (Next.js) — use builder stage for dev mode with hot reload
docker_build(
    'bamf-web',
    context='.',
    dockerfile='docker/Dockerfile.web',
    target='builder',
    entrypoint=['npx', 'next', 'dev', '-H', '0.0.0.0'],
    live_update=[
        sync('./web/src', '/app/src'),
        sync('./web/public', '/app/public'),
    ],
)

# Agent (Go)
docker_build(
    'bamf-agent',
    context='.',
    dockerfile='docker/Dockerfile.agent',
    build_args={
        'VERSION': 'dev',
        'GIT_COMMIT': 'local',
    },
)

# ─────────────────────────────────────────────────────────────────────────────
# Kubernetes Resources
# ─────────────────────────────────────────────────────────────────────────────

# Load Helm chart with local overrides
k8s_yaml(helm(
    'helm/bamf',
    name='bamf',
    namespace='bamf',
    values=['helm/bamf/values.yaml', 'helm/bamf/values-local.yaml'],
    set=[
        'api.image.repository=bamf-api',
        'api.image.tag=latest',
        'api.image.pullPolicy=Never',
        'bridge.image.repository=bamf-bridge',
        'bridge.image.tag=latest',
        'bridge.image.pullPolicy=Never',
        'web.image.repository=bamf-web',
        'web.image.tag=latest',
        'web.image.pullPolicy=Never',
        'web.standalone=true',
        'postgresql.bundled.enabled=true',
        'postgresql.external.enabled=false',
        'redis.bundled.enabled=true',
        'redis.external.enabled=false',
        'tls.certManager.enabled=false',
        'migrations.enabled=true',
        # Agent image overrides for local dev
        'agent.image.repository=bamf-agent',
        'agent.image.tag=latest',
        'agent.image.pullPolicy=Never',
    ],
))

# ─────────────────────────────────────────────────────────────────────────────
# Resource Configuration
# ─────────────────────────────────────────────────────────────────────────────

# API Server (accessed via Ingress at https://bamf.local)
k8s_resource(
    'bamf-api',
    labels=['backend'],
    resource_deps=['bamf-postgresql', 'setup-certificates'],
)

# Bridge (tunnel gateway — non-HTTP TCP ports exposed via LoadBalancer,
# same as production. k3s svclb binds the ports on localhost.)
k8s_resource(
    'bamf-bridge',
    labels=['backend'],
    resource_deps=['bamf-api'],
)

# Web UI (accessed via Ingress at https://bamf.local)
k8s_resource(
    'bamf-web',
    labels=['frontend'],
    resource_deps=['bamf-api'],
)

# PostgreSQL
k8s_resource(
    'bamf-postgresql',
    labels=['database'],
)

# Redis
k8s_resource(
    'bamf-redis',
    labels=['database'],
)

# Agent (provides access to cluster resources)
k8s_resource(
    'bamf-agent',
    labels=['backend'],
    resource_deps=['bamf-bootstrap-1'],
)

# Migrations job (name includes revision suffix from Helm)
k8s_resource(
    'bamf-migrations-1',
    labels=['jobs'],
    resource_deps=['bamf-postgresql'],
)

# Bootstrap job (creates initial admin user, runs on first install)
k8s_resource(
    'bamf-bootstrap-1',
    labels=['jobs'],
    resource_deps=['bamf-migrations-1'],
)

# ─────────────────────────────────────────────────────────────────────────────
# Echo Server (for HTTP proxy E2E testing)
# ─────────────────────────────────────────────────────────────────────────────

# Simple Python echo server that returns all request headers in the response body.
# Used to verify HTTP proxy header rewriting.
k8s_yaml(blob('''
apiVersion: v1
kind: ConfigMap
metadata:
  name: bamf-echo-server
  namespace: bamf
data:
  echo.py: |
    """Minimal HTTP echo server for proxy testing.

    Returns JSON with all request headers, method, path, and query string.
    """
    import json
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class EchoHandler(BaseHTTPRequestHandler):
        def do_ANY(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            response = json.dumps({
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body.decode("utf-8", errors="replace"),
            }, indent=2)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Echo-Server", "bamf-test")
            self.end_headers()
            self.wfile.write(response.encode())

        # Handle all HTTP methods
        do_GET = do_ANY
        do_POST = do_ANY
        do_PUT = do_ANY
        do_DELETE = do_ANY
        do_PATCH = do_ANY
        do_HEAD = do_ANY
        do_OPTIONS = do_ANY

    if __name__ == "__main__":
        server = HTTPServer(("0.0.0.0", 8080), EchoHandler)
        print("Echo server listening on :8080")
        server.serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bamf-echo
  namespace: bamf
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bamf-echo
  template:
    metadata:
      labels:
        app: bamf-echo
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          command: ["python", "/app/echo.py"]
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: echo-script
              mountPath: /app
      volumes:
        - name: echo-script
          configMap:
            name: bamf-echo-server
---
apiVersion: v1
kind: Service
metadata:
  name: bamf-echo
  namespace: bamf
spec:
  selector:
    app: bamf-echo
  ports:
    - port: 8080
      targetPort: 8080
'''))

k8s_resource(
    'bamf-echo',
    labels=['test'],
)

# ─────────────────────────────────────────────────────────────────────────────
# SSH Server (for SSH tunnel E2E testing)
# ─────────────────────────────────────────────────────────────────────────────

# OpenSSH server for testing bamf ssh → API → Bridge → Agent → SSH flow.
# Uses linuxserver/openssh-server which configures sshd via env vars.
k8s_yaml(blob('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bamf-test-ssh
  namespace: bamf
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bamf-test-ssh
  template:
    metadata:
      labels:
        app: bamf-test-ssh
    spec:
      containers:
        - name: sshd
          image: linuxserver/openssh-server:latest
          env:
            - name: PUID
              value: "1000"
            - name: PGID
              value: "1000"
            - name: PASSWORD_ACCESS
              value: "true"
            - name: USER_NAME
              value: "testuser"
            - name: USER_PASSWORD
              value: "testpass"
          ports:
            - containerPort: 2222
---
apiVersion: v1
kind: Service
metadata:
  name: bamf-test-ssh
  namespace: bamf
spec:
  selector:
    app: bamf-test-ssh
  ports:
    - port: 22
      targetPort: 2222
'''))

k8s_resource(
    'bamf-test-ssh',
    labels=['test'],
)

# ─────────────────────────────────────────────────────────────────────────────
# Local Commands
# ─────────────────────────────────────────────────────────────────────────────

# Run Python tests (containerized to avoid local PYTHONPATH issues)
local_resource(
    'test-python',
    cmd='docker compose -f docker-compose.test.yml run --rm --build test',
    labels=['tests'],
    auto_init=False,
    trigger_mode=TRIGGER_MODE_MANUAL,
)

# Run Go tests
local_resource(
    'test-go',
    cmd='go test -v ./...',
    labels=['tests'],
    auto_init=False,
    trigger_mode=TRIGGER_MODE_MANUAL,
)

# Run linters
local_resource(
    'lint',
    cmd='golangci-lint run ./... && docker compose -f docker-compose.test.yml run --rm --build lint',
    labels=['tests'],
    auto_init=False,
    trigger_mode=TRIGGER_MODE_MANUAL,
)

# Build CLI locally
local_resource(
    'build-cli',
    cmd='go build -o bin/bamf ./cmd/bamf',
    labels=['build'],
    auto_init=False,
    trigger_mode=TRIGGER_MODE_MANUAL,
)
