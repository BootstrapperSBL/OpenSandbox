#!/usr/bin/env bash
# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# env.sh — fast-sandbox integration environment lifecycle: bring-up
# (preflight -> kind -> RustFS -> control plane -> firecracker runtime ->
# server + gateway -> golden-image template -> SandboxPool), teardown
# (down), health (status) and pool re-apply (pool). No verify stages: the
# entry script (integration.sh) chains env_up_stages with the
# verify/*.sh suites; this file can also run them standalone.
#
# Usage:
#   scripts/fast-sandbox-env/env.sh up       # provision the full environment
#   scripts/fast-sandbox-env/env.sh down     # teardown, host left clean
#   scripts/fast-sandbox-env/env.sh status   # component/pool/DART/OpenSandbox health
#   scripts/fast-sandbox-env/env.sh pool     # re-apply the SandboxPool only
# Environment overrides: see the header of integration.sh.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

preflight() {
	[[ "$(uname -s)" == "Linux" ]] \
		|| die "this environment requires a Linux host with KVM (run it on the remote development VM)"
	command -v docker >/dev/null || die "docker is required"
	command -v go >/dev/null || die "go is required (>=1.25, used by make images and gen-registry)"
	ensure_tool kind
	ensure_tool kubectl
	ensure_tool helm
	ensure_tool jq
	docker info >/dev/null 2>&1 || die "docker daemon is not reachable"
	local cgver
	cgver="$(docker info --format '{{.CgroupVersion}}' 2>/dev/null || true)"
	log "docker cgroup version=$cgver"
	# kind requires cgroup v2; v1 hosts fail kubepods cgroup creation.
	if [[ "$cgver" == "1" ]]; then
		die "docker cgroup Version is 1; kind requires cgroup v2. Enable it with the kernel cmdline 'systemd.unified_cgroup_hierarchy=1' and reboot"
	fi
	[[ -e /dev/kvm ]] || die "/dev/kvm is missing on this host (KVM required)"
	# Fail fast per heavy-data target instead of ENOSPC mid-run.
	local min_free_kb=$((20 * 1024 * 1024)) avail_kb target xfs_dir
	xfs_dir="${XFS_LOOP_FILE%/*}"
	mkdir -p "$WORK" "$RUSTFS_DATA" "$xfs_dir" 2>/dev/null || true
	local -a targets=("$WORK" "$RUSTFS_DATA" "$xfs_dir")
	for target in "${targets[@]}"; do
		avail_kb="$(df -Pk "$target" 2>/dev/null | awk 'NR==2 {print $4}')"
		[[ "$avail_kb" =~ ^[0-9]+$ ]] || die "cannot determine free disk space on $target"
		if (( avail_kb < min_free_kb )); then
			die "$target has $((avail_kb / 1024 / 1024))G free; at least 20G is required (built images, XFS StateRoot, RustFS artifacts). Free space (docker system prune / old kind clusters) or point WORK / RUSTFS_DATA / XFS_LOOP_FILE at a bigger volume"
		fi
		log "disk headroom: $target has $((avail_kb / 1024 / 1024 / 1024))G free"
	done
	# Fail fast on busy host ports instead of a cryptic docker/kind bind error.
	local port
	for port in "$RUSTFS_PORT" "$RUSTFS_CONSOLE_PORT" "$SERVER_HOST_PORT" "$GATEWAY_HOST_PORT"; do
		if host_port_busy "$port"; then
			die "127.0.0.1:$port is already in use (check 'ss -ltnp' / 'docker ps'); free it, or set RUSTFS_PORT / RUSTFS_CONSOLE_PORT / SERVER_HOST_PORT / GATEWAY_HOST_PORT"
		fi
	done
	ensure_image "$RUSTFS_IMAGE"
	ensure_image "$RC_IMAGE"
	pass "preflight"
}

sysctl_set() {
	local current
	current="$(sysctl -n fs.inotify.max_user_instances)"
	[[ "$current" -ge "$INOTIFY_VALUE" ]] && return 0
	echo "$current" > "$SYSCTL_BACKUP"
	log "sysctl fs.inotify.max_user_instances: $current -> $INOTIFY_VALUE"
	sudo sysctl -w fs.inotify.max_user_instances="$INOTIFY_VALUE" >/dev/null
}

sysctl_restore() {
	[[ -f "$SYSCTL_BACKUP" ]] || return 0
	local previous
	previous="$(cat "$SYSCTL_BACKUP")"
	log "restoring fs.inotify.max_user_instances -> $previous"
	sudo sysctl -w fs.inotify.max_user_instances="$previous" >/dev/null || true
	rm -f "$SYSCTL_BACKUP"
}

# --- stage: fast-sandbox checkout @ master ---------------------------------------------

# Scratch Go tool run inside the fast-sandbox module (imports
# internal/registryconfig); removed before dirty checks and on down.
FSB_GEN_DIR="$FSB_DIR/.fast-sandbox-env-gen"

ensure_fsb() {
	if [[ ! -d "$FSB_DIR/.git" ]]; then
		log "cloning $FSB_REPO into $FSB_DIR"
		git clone "$FSB_REPO" "$FSB_DIR" || die "clone failed; check network"
	fi
	rm -rf "$FSB_GEN_DIR"
	[[ -z "$(git -C "$FSB_DIR" status --porcelain)" ]] \
		|| die "fast-sandbox checkout at $FSB_DIR has local changes; delete it to re-clone or point FSB_DIR at a clean checkout"
	# Raw SHA fetch needs allow-reachable-sha1-in-want; full fetch otherwise.
	if ! git -C "$FSB_DIR" fetch -q origin "$FSB_COMMIT" 2>/dev/null; then
		git -C "$FSB_DIR" fetch -q origin '+refs/heads/*:refs/remotes/origin/*' \
			|| die "git fetch failed for $FSB_REPO"
	fi
	git -C "$FSB_DIR" rev-parse --verify --quiet "$FSB_COMMIT^{commit}" >/dev/null \
		|| die "pinned commit $FSB_COMMIT is not reachable from $FSB_REPO"
	if [[ "$(git -C "$FSB_DIR" rev-parse HEAD)" != "$FSB_COMMIT" ]]; then
		git -C "$FSB_DIR" clean -ffdx
	fi
	git -C "$FSB_DIR" checkout --force -q "$FSB_COMMIT" \
		|| die "git checkout $FSB_COMMIT failed"
	[[ "$(git -C "$FSB_DIR" rev-parse HEAD)" == "$FSB_COMMIT" ]] \
		|| die "fast-sandbox checkout is not at the pinned commit $FSB_COMMIT"
	log "fast-sandbox @ pinned $(git -C "$FSB_DIR" rev-parse --short HEAD) (manifests/third-party/fast-sandbox.commit)"
	pass "fast-sandbox checkout ready"
}

# --- stage: images ---------------------------------------------------------------------

build_images() {
	log "building fast-sandbox images (pinned commit, firecracker scope) via manifests/release/build-fast-sandbox.sh"
	# Same checkout and defaults as the standalone builder: env and published
	# build paths cannot drift.
	FSB_SRC_DIR="$FSB_DIR" "$OSB_ROOT/manifests/release/build-fast-sandbox.sh" \
		|| die "fast-sandbox image build failed"
	log "building the OpenSandbox egress image ($IMG_EGRESS)"
	# Context is the repo root (COPYs components/egress + components/internal).
	# shellcheck disable=SC2086
	docker build ${DOCKER_BUILD_FLAGS:-} --quiet \
		-f "$OSB_ROOT/components/egress/Dockerfile" -t "$IMG_EGRESS" "$OSB_ROOT" >/dev/null \
		|| die "egress image build failed"
	log "building the OpenSandbox server image ($IMG_SERVER)"
	# Context is server/ (self-contained Dockerfile).
	# shellcheck disable=SC2086
	docker build ${DOCKER_BUILD_FLAGS:-} --quiet \
		-f "$OSB_ROOT/server/Dockerfile" -t "$IMG_SERVER" "$OSB_ROOT/server" >/dev/null \
		|| die "server image build failed"
	log "building the OpenSandbox ingress image ($IMG_INGRESS)"
	# shellcheck disable=SC2086
	docker build ${DOCKER_BUILD_FLAGS:-} --quiet \
		-f "$OSB_ROOT/components/ingress/Dockerfile" -t "$IMG_INGRESS" "$OSB_ROOT" >/dev/null \
		|| die "ingress image build failed"
	pass "images built (fast-sandbox + OpenSandbox)"
}

# --- stage: XFS StateRoot (reflink CoW per-sandbox rootfs) ------------------------------

XFS_STATEROOT="${XFS_STATEROOT:-1}"
XFS_LOOP_FILE="${XFS_LOOP_FILE:-$WORK/fast-sandbox.img}"
XFS_SIZE="${XFS_SIZE:-24G}"
XFS_MOUNT_POINT="${XFS_MOUNT_POINT:-/var/lib/fast-sandbox}"

ensure_xfsprogs() {
	command -v mkfs.xfs >/dev/null 2>&1 && return 0
	log "installing xfsprogs (mkfs.xfs)"
	if command -v apt-get >/dev/null 2>&1; then
		sudo_ apt-get install -y xfsprogs >/dev/null
	elif command -v yum >/dev/null 2>&1; then
		sudo_ yum install -y xfsprogs >/dev/null
	else
		die "xfsprogs not installed and no supported package manager"
	fi
}

stateroot_xfs_up() {
	[[ "$XFS_STATEROOT" == 1 ]] || {
		sudo_ mkdir -p "$XFS_MOUNT_POINT"
		log "XFS StateRoot disabled (XFS_STATEROOT=0); per-sandbox rootfs pays a full copy"
		return 0
	}
	if findmnt -no FSTYPE "$XFS_MOUNT_POINT" 2>/dev/null | grep -qx xfs; then
		# Leftover from a run killed before teardown: scrub, and recreate the
		# image if still below the agent's min-free floor (it strips the kvm
		# node label and template builds stop scheduling).
		stateroot_scrub
		if (( $(stateroot_free_gib) >= XFS_MIN_FREE_GIB )); then
			pass "XFS StateRoot ready (reflink CoW rootfs, scrubbed)"
			return 0
		fi
		log "StateRoot below ${XFS_MIN_FREE_GIB}GiB free after scrub; recreating the XFS image"
		sudo_ umount "$XFS_MOUNT_POINT" || die "unmount $XFS_MOUNT_POINT failed"
		rm -f "$XFS_LOOP_FILE"
	fi
	ensure_xfsprogs
	if [[ ! -f "$XFS_LOOP_FILE" ]]; then
		log "creating sparse XFS image $XFS_LOOP_FILE (virtual $XFS_SIZE)"
		truncate -s "$XFS_SIZE" "$XFS_LOOP_FILE"
		sudo_ mkfs.xfs -f "$XFS_LOOP_FILE" >/dev/null 2>&1 || die "mkfs.xfs failed on $XFS_LOOP_FILE"
	fi
	sudo_ mkdir -p "$XFS_MOUNT_POINT"
	sudo_ mount -o noatime "$XFS_LOOP_FILE" "$XFS_MOUNT_POINT" \
		|| die "mount $XFS_LOOP_FILE at $XFS_MOUNT_POINT failed (loop support? try XFS_STATEROOT=0)"
	local a b
	a="$XFS_MOUNT_POINT/.reflink-a"
	b="$XFS_MOUNT_POINT/.reflink-b"
	printf 'probe' | sudo_ tee "$a" >/dev/null
	if sudo_ cp --reflink=always "$a" "$b"; then
		sudo_ rm -f "$a" "$b"
		pass "XFS StateRoot ready (reflink CoW rootfs)"
	else
		sudo_ rm -f "$a" "$b"
		die "reflink probe failed on $XFS_MOUNT_POINT (CoW rootfs would not work)"
	fi
}

# Purge per-node runtime caches in the mounted StateRoot (shared by down()
# and the reuse branch of stateroot_xfs_up); snapshots/ leaks across runs.
stateroot_scrub() {
	local node_dir
	for node_dir in "$XFS_MOUNT_POINT"/*/; do
		[[ -d "${node_dir}firecracker" ]] || continue
		log "purging node runtime cache under ${node_dir%/}"
		sudo_ rm -rf "${node_dir}firecracker/images" \
			"${node_dir}firecracker/agent" \
			"${node_dir}firecracker/jails" \
			"${node_dir}firecracker/cache" \
			"${node_dir}firecracker/snapshots" 2>/dev/null || true
	done
}

# Free space on the mounted StateRoot, in GiB (GNU df).
stateroot_free_gib() {
	df -BG --output=avail "$XFS_MOUNT_POINT" 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0
}
XFS_MIN_FREE_GIB="${XFS_MIN_FREE_GIB:-12}"

stateroot_xfs_down() {
	[[ "$XFS_STATEROOT" == 1 ]] || return 0
	if findmnt -no SOURCE "$XFS_MOUNT_POINT" 2>/dev/null | grep -q "$(basename "$XFS_LOOP_FILE")"; then
		log "unmounting XFS StateRoot $XFS_MOUNT_POINT"
		sudo_ umount "$XFS_MOUNT_POINT"
	fi
	rm -f "$XFS_LOOP_FILE"
}

# --- stage: kind cluster -----------------------------------------------------------------

render_kind_config() { # > $GEN_DIR/kind-cluster.yaml
	local src="$MANIFESTS_DIR/cluster/kind-cluster.yaml" out="$GEN_DIR/kind-cluster.yaml"
	mkdir -p "$GEN_DIR"
	cp "$src" "$out"
	if [[ "$KIND_SINGLE" == "1" ]]; then
		# Strip the worker node: cache-only topology, no peer traffic.
		awk '/^- role: worker/ {exit} {print}' "$out" > "$out.tmp" && mv "$out.tmp" "$out"
		log "single-node topology (KIND_SINGLE=1: no worker, no peer traffic)"
	fi
	if [[ -n "${DOCKER_MIRROR:-}" ]]; then
		# Host-specific, hence opt-in; one TOML endpoint ARRAY (repeated
		# endpoint keys would override each other).
		local block_file="$GEN_DIR/docker-mirror-block.yaml" mirror trimmed endpoints=""
		IFS=',' read -ra mirrors <<<"$DOCKER_MIRROR"
		for mirror in "${mirrors[@]}"; do
			trimmed="$(printf '%s' "$mirror" | tr -d '[:space:]')"
			[[ -n "$trimmed" ]] || continue
			[[ -z "$endpoints" ]] && endpoints="\"$trimmed\"" || endpoints+=", \"$trimmed\""
		done
		[[ -n "$endpoints" ]] || die "DOCKER_MIRROR produced no usable endpoints"
		{
			echo 'containerdConfigPatches:'
			echo '- |-'
			echo '  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]'
			echo "    endpoint = [$endpoints]"
		} > "$block_file"
		awk -v block_file="$block_file" '
			NR == FNR { block = block $0 "\n"; next }
			/^nodes:/ && !done { printf "%s", block; done = 1 }
			{ print }
		' "$block_file" "$out" > "$out.tmp" && mv "$out.tmp" "$out"
		rm -f "$block_file"
		log "docker.io containerd mirrors injected: $endpoints"
	fi
	# extraPortMappings publish the server/gateway on the host; they exist
	# only at cluster creation, so a cluster reused without them stays
	# cluster-internal.
	local ports_file="$GEN_DIR/osb-ports-block.yaml"
	{
		echo '  extraPortMappings:'
		echo "  - containerPort: $SERVER_NODEPORT"
		echo "    hostPort: $SERVER_HOST_PORT"
		echo '    listenAddress: 127.0.0.1'
		echo '    protocol: TCP'
		echo "  - containerPort: $GATEWAY_NODEPORT"
		echo "    hostPort: $GATEWAY_HOST_PORT"
		echo '    listenAddress: 127.0.0.1'
		echo '    protocol: TCP'
	} > "$ports_file"
	awk -v block_file="$ports_file" '
		NR == FNR { block = block $0 "\n"; next }
		/^- role: control-plane/ && !done { print; printf "%s", block; done = 1; next }
		{ print }
	' "$ports_file" "$out" > "$out.tmp" && mv "$out.tmp" "$out"
	rm -f "$ports_file"
	log "server on 127.0.0.1:$SERVER_HOST_PORT, gateway on 127.0.0.1:$GATEWAY_HOST_PORT (NodePorts $SERVER_NODEPORT/$GATEWAY_NODEPORT)"
}

kind_up() {
	local create_args=() kind_config="$GEN_DIR/kind-cluster.yaml"
	[[ -f "$kind_config" ]] || die "kind config not rendered ($kind_config)"
	[[ "$KIND_RETAIN" == 1 ]] && create_args+=(--retain)
	if [[ -n "$(kind get clusters 2>/dev/null | grep -x "$KIND_CLUSTER" || true)" ]]; then
		log "cluster $KIND_CLUSTER already exists; reusing (run down first for a clean rebuild)"
	else
		if [[ -n "${KIND_NODE_IMAGE:-}" ]]; then
			log "pulling kind node image $KIND_NODE_IMAGE (this can take minutes)"
			ensure_image "$KIND_NODE_IMAGE" || die "kind node image unavailable locally and pull failed (KIND_NODE_IMAGE=$KIND_NODE_IMAGE)"
			create_args+=(--image "$KIND_NODE_IMAGE")
		else
			log "creating cluster (pulling kindest/node may take minutes; set KIND_NODE_IMAGE to a mirror if it fails)"
		fi
		kind create cluster --name "$KIND_CLUSTER" \
			${create_args+"${create_args[@]}"} --config "$kind_config" > "$LOGS_DIR/kind-create.log" 2>&1 || {
			local rc=$?
			tail -40 "$LOGS_DIR/kind-create.log" >&2 || true
			log "kind create failed (full log: $LOGS_DIR/kind-create.log)" || true
			return "$rc"	# through ERR, so diagnostics + --auto-clean run
		}
		pass "kind cluster created"
	fi
	local node
	for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
		docker exec "$node" sh -c 'test -e /dev/kvm' || die "KVM not visible inside the kind node container $node"
		log "node $node: /dev/kvm visible"
	done
	if [[ "$KIND_SINGLE" != "1" ]]; then
		# Untaint the control plane: agent/fastlet/builder must schedule on
		# BOTH nodes for P2P peer traffic.
		kubectl taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true
		log "control-plane taint removed (both nodes schedulable for the P2P topology)"
	fi
	pass "kind cluster ready (KVM passthrough + labels on every node)"
}

# --- stage: RustFS + credentials ------------------------------------------------------------

rustfs_up() {
	docker rm -f "$RUSTFS_CONTAINER" >/dev/null 2>&1 || true
	# RustFS runs as UID/GID 10001 and owns the bind-mounted store.
	sudo_ rm -rf "$RUSTFS_DATA"
	mkdir -p "$RUSTFS_DATA"
	sudo_ chown -R 10001:10001 "$RUSTFS_DATA"
	mkdir -p "$RC_CONFIG_DIR"
	chmod 700 "$RC_CONFIG_DIR"
	local net
	net="$(kind_network)"
	# On the kind network: pods reach the container IP directly (no
	# docker-proxy/hairpin issues); 127.0.0.1 publishes serve the host.
	docker run -d --name "$RUSTFS_CONTAINER" --network "$net" \
		-p 127.0.0.1:"$RUSTFS_PORT":"$RUSTFS_CONTAINER_PORT" -p 127.0.0.1:"$RUSTFS_CONSOLE_PORT":9001 \
		-e RUSTFS_ACCESS_KEY="$RUSTFS_AK" -e RUSTFS_SECRET_KEY="$RUSTFS_SK" \
		-e RUSTFS_ADDRESS=":$RUSTFS_CONTAINER_PORT" \
		-e RUSTFS_CONSOLE_ADDRESS=:9001 -e RUSTFS_CONSOLE_ENABLE=true \
		-v "$RUSTFS_DATA:/data" \
		"$RUSTFS_IMAGE" >/dev/null
	local attempt
	for attempt in $(seq 1 30); do
		if curl -fsS "http://127.0.0.1:$RUSTFS_PORT/health" >/dev/null 2>&1; then break; fi
		sleep 1
		[[ "$attempt" == 30 ]] && die "RustFS did not become healthy"
	done
	rc alias set chain "http://127.0.0.1:$RUSTFS_PORT" "$RUSTFS_AK" "$RUSTFS_SK" >/dev/null 2>&1 \
		|| die "could not configure the RustFS rc alias"
	for attempt in $(seq 1 30); do
		if rc ls chain/ >/dev/null 2>&1; then break; fi
		sleep 1
		[[ "$attempt" == 30 ]] && die "RustFS S3 API did not become ready for authenticated bucket listing"
	done
	rc mb "chain/$RUSTFS_BUCKET" >/dev/null
	pass "RustFS up (bucket=$RUSTFS_BUCKET)"
}

resolve_rustfs_endpoint() {
	if [[ -n "$RUSTFS_ENDPOINT" ]]; then
		log "RustFS endpoint (env): $RUSTFS_ENDPOINT"
	else
		local net ips ip
		net="$(kind_network)"
		ips="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{$v.IPAddress}} {{end}}' "$RUSTFS_CONTAINER")"
		ip="$(printf '%s' "$ips" | tr ' ' '\n' | grep -A1 -x "^$net$" | tail -1)"
		[[ -n "$ip" ]] || die "could not find the RustFS IP on network $net (inspect: $ips)"
		# Container port, not the host publish: kind-network clients hit the
		# container IP directly.
		RUSTFS_ENDPOINT="http://$ip:$RUSTFS_CONTAINER_PORT"
		log "RustFS endpoint (kind network IP): $RUSTFS_ENDPOINT"
	fi
	local net
	net="$(kind_network)"
	docker run --rm --network "$net" --user "$(id -u):$(id -g)" -e RC_CONFIG_DIR=/config \
		-e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= \
		-e http_proxy= -e https_proxy= -e all_proxy= \
		-v "$RC_CONFIG_DIR:/config" "$RC_IMAGE" alias set kind-rustfs \
		"$RUSTFS_ENDPOINT" "$RUSTFS_AK" "$RUSTFS_SK" >/dev/null 2>&1 \
		|| die "RustFS unreachable from the kind network at $RUSTFS_ENDPOINT (override RUSTFS_ENDPOINT)"
	docker run --rm --network "$net" --user "$(id -u):$(id -g)" -e RC_CONFIG_DIR=/config \
		-e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= \
		-e http_proxy= -e https_proxy= -e all_proxy= \
		-v "$RC_CONFIG_DIR:/config" "$RC_IMAGE" ls "kind-rustfs/$RUSTFS_BUCKET" >/dev/null 2>&1 \
		|| die "RustFS authenticated bucket access failed from the kind network at $RUSTFS_ENDPOINT"
	pass "RustFS reachable from the kind network"
}

# gen_registry builds the agent registry JSON via fast-sandbox's
# registryconfig package; the write pair covers checkpoint publication.
gen_registry() { # host username password endpoint [write-username write-password] > registry.json
	mkdir -p "$FSB_GEN_DIR"
	cat > "$FSB_GEN_DIR/gen-registry.go" <<'EOF'
package main

import (
	"fmt"
	"os"

	"fast-sandbox/internal/registryconfig"
)

func main() {
	if len(os.Args) != 5 && len(os.Args) != 7 {
		fmt.Fprintln(os.Stderr, "usage: gen-registry <host> <username> <password> <endpoint> [write-username write-password]")
		os.Exit(1)
	}
	credential := registryconfig.Credential{
		Host: os.Args[1], Username: os.Args[2], Password: os.Args[3], Endpoint: os.Args[4],
	}
	if len(os.Args) == 7 {
		// Optional publish (write) pair: empty keeps the store read-only.
		credential.WriteUsername, credential.WritePassword = os.Args[5], os.Args[6]
	}
	compiled, err := registryconfig.NewCompiled([]registryconfig.Credential{credential})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	payload, err := compiled.Marshal()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(payload)
}
EOF
	(cd "$FSB_DIR" && GOTOOLCHAIN=local go run .fast-sandbox-env-gen/gen-registry.go "$@")
}

credentials_up() {
	# Namespaces exist even after a partial up (resume support).
	kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
	kubectl create namespace "$RESOURCE_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
	local host
	host="${RUSTFS_ENDPOINT#http://}"
	host="${host#https://}"
	# Publish credentials for the builder Pod (dataplane namespace).
	kubectl -n "$RESOURCE_NS" create secret generic sandbox-oss-credentials \
		--from-literal=accessKeyId="$RUSTFS_AK" \
		--from-literal=secretAccessKey="$RUSTFS_SK" \
		--from-literal=endpoint="$RUSTFS_ENDPOINT" \
		--from-literal=region=us-east-1 \
		--dry-run=client -o yaml | kubectl apply -f - >/dev/null
	# Agent pull+publish credentials (the write pair covers checkpoints).
	gen_registry "$host" "$RUSTFS_AK" "$RUSTFS_SK" "$RUSTFS_ENDPOINT" "$RUSTFS_AK" "$RUSTFS_SK" \
		> "$WORK/agent-registry.json"
	jq -e '.credentials[0].writeUsername' "$WORK/agent-registry.json" >/dev/null \
		|| die "generated agent registry carries no write credential"
	kubectl -n "$NS" create secret generic fast-sandbox-agent-registry \
		--from-file=registry.json="$WORK/agent-registry.json" \
		--dry-run=client -o yaml | kubectl apply -f - >/dev/null
	# Pull credentials for the fastlet; the artifact-store ConfigMap is
	# rendered by charts/fast-sandbox at install time.
	kubectl -n "$RESOURCE_NS" create secret docker-registry registry-rustfs \
		--docker-server="$host" --docker-username="$RUSTFS_AK" --docker-password="$RUSTFS_SK" \
		--dry-run=client -o yaml | kubectl apply -f - >/dev/null
	kubectl -n "$RESOURCE_NS" create configmap fast-sandbox-registry \
		--from-literal="registries.yaml=registries:
  - host: $host
    secretRef:
      name: registry-rustfs
" \
		--dry-run=client -o yaml | kubectl apply -f - >/dev/null
	pass "credentials written (publish/pull)"
}

# --- stage: control plane -------------------------------------------------------------------

# helm is only a renderer; the cluster keeps no helm release state, so
# re-runs stay plain idempotent `kubectl apply`.
helm_render() { # release chart ns out [set-args...]
	local release="$1" chart="$2" ns="$3" out="$4"
	shift 4
	helm template "$release" "$chart" --namespace "$ns" "$@" > "$out" \
		|| die "helm template $chart failed"
}

apply_ns() { # ns -> ensure the namespace exists (idempotent)
	kubectl create namespace "$1" --dry-run=client -o yaml 2>/dev/null |
		kubectl apply -f - >/dev/null
}

control_plane_up() {
	# Charts are the source of truth (CRDs + RBAC + control plane), replacing
	# the fast-sandbox checkout's kustomize applies and env-owned node manifests.
	apply_ns "$NS"
	helm_render fsb-base "$OSB_ROOT/manifests/charts/base" "$NS" "$GEN_DIR/fsb-base.yaml"
	kubectl apply -f "$GEN_DIR/fsb-base.yaml" >/dev/null
	helm_render fast-sandbox "$OSB_ROOT/manifests/charts/fast-sandbox" "$NS" \
		"$GEN_DIR/fast-sandbox.yaml" \
		--set controller.image.repository="$(image_repo "$IMG_CONTROLLER")" \
		--set controller.image.tag="$(image_tag "$IMG_CONTROLLER")" \
		--set controller.sandboxtemplateBuilderImage="$IMG_BUILDER" \
		--set controller.fastletProxyImage="$IMG_FASTLET_PROXY" \
		--set janitor.image.repository="$(image_repo "$IMG_JANITOR")" \
		--set janitor.image.tag="$(image_tag "$IMG_JANITOR")" \
		--set runtime.image.repository="$(image_repo "$IMG_RUNTIME")" \
		--set runtime.image.tag="$(image_tag "$IMG_RUNTIME")" \
		--set artifactStore.store="s3://$RUSTFS_BUCKET/publish" \
		--set artifactStore.endpoint="$RUSTFS_ENDPOINT"
	kubectl apply -f "$GEN_DIR/fast-sandbox.yaml" >/dev/null
	local image
	for image in "$IMG_CONTROLLER" "$IMG_FASTLET" "$IMG_FASTLET_PROXY" \
		"$IMG_JANITOR" "$IMG_RUNTIME" "$IMG_EGRESS"; do
		kind load docker-image "$image" --name "$KIND_CLUSTER" >/dev/null
	done
	wait_for "controller deployment ready" 120 \
		kubectl -n "$NS" rollout status deploy/fast-sandbox-controller --timeout=10s
	local crd
	for crd in sandboxpools sandboxtemplates sandboxes sandboxsnapshots; do
		kubectl get crd "$crd.sandbox.fast.io" >/dev/null 2>&1 || die "CRD $crd missing"
	done
	kubectl get crd batchsandboxes.sandbox.opensandbox.io >/dev/null 2>&1 \
		|| die "CRD batchsandboxes.sandbox.opensandbox.io missing"
	pass "CRDs + control plane ready (charts @ pinned $(git -C "$FSB_DIR" rev-parse --short HEAD))"
}

# --- stage: firecracker runtime (node readiness + DART P2P) -----------------------------------

runtime_node_labeled() { # node -> 0 when the agent applied both labels + condition
	local node="$1"
	kubectl get node "$node" -o json 2>/dev/null | jq -e \
		--arg fc "$FC_NODE_LABEL" --arg kvm "$KVM_NODE_LABEL" '
		(.metadata.labels[$fc] == "true") and
		(.metadata.labels[$kvm] == "true") and
		([(.status.conditions // [])[]?
		  | select(.type == "FirecrackerReady" and .status == "True")] | length > 0)
	' >/dev/null
}

runtime_pods() {
	kubectl -n "$NS" get pods -l component=firecracker-runtime -o jsonpath='{.items[*].metadata.name}' 2>/dev/null
}

dart_roster_ready() { # pod expected-members
	local pod="$1" expected="$2" members
	members="$(kubectl exec -n "$NS" "$pod" -- sh -c \
		'curl -fsS --noproxy "*" http://127.0.0.1:8147/admin/members' 2>/dev/null || true)"
	[[ "$(printf '%s' "$members" | grep -o '"id":' | wc -l | tr -d ' ')" == "$expected" ]]
}

runtime_up() {
	# DaemonSet + dart Service ship with charts/fast-sandbox; credentials land
	# in credentials_up before this stage.
	wait_for "firecracker-runtime DaemonSet ready" 120 \
		kubectl -n "$NS" rollout status daemonset/firecracker-runtime --timeout=10s

	# Positive wiring assertions: DART admin plane up, agent p2pUp=true
	# (a missing P2P daemon only degrades pulls to direct S3).
	local pod uid node pods
	pods="$(runtime_pods)"
	for pod in $pods; do
		uid="$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.metadata.uid}')"
		node="$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.nodeName}')"
		wait_for "dart admin /healthz on $node" 30 \
			kubectl exec -n "$NS" "$pod" -- sh -c \
				"curl -fsS --noproxy '*' http://127.0.0.1:8147/healthz | grep -q ok"
		wait_for "agent health p2pUp on $node" 30 \
			kubectl exec -n "$NS" "$pod" -- sh -c \
				"curl -fsS --noproxy '*' --unix-socket /run/fast-sandbox/firecracker/runtime.sock -H 'Content-Type: application/json' -d '{\"podUid\":\"$uid\",\"namespace\":\"$NS\"}' http://firecracker-agent/v1/health | grep -q '\"p2pUp\":true'"
		log "dart: $node dart pid=$(kubectl exec -n "$NS" "$pod" -- sh -c 'pgrep -x dart')"
	done
	# P2P roster: every daemon must see every peer before any pull, so later
	# nodes are fed by peers instead of the origin.
	local expected_members
	expected_members="$(printf '%s' "$pods" | wc -w | tr -d ' ')"
	for pod in $pods; do
		node="$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.nodeName}')"
		wait_for "dart roster full on $node ($expected_members members)" 90 \
			dart_roster_ready "$pod" "$expected_members"
	done
	# The readiness loop applies labels + FirecrackerReady itself.
	for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
		wait_for "node $node labeled + FirecrackerReady" 120 \
			runtime_node_labeled "$node"
	done
	pass "firecracker-runtime healthy + DART roster=$expected_members + nodes FirecrackerReady"
}

# --- stage (opensandbox CLI): SandboxTemplate golden image ---------------------

wait_succeeded() { # description attempts probe probe_failed
	local description="$1" attempts="$2" probe="$3" probe_failed="$4" attempt=0
	while ! "$probe" >/dev/null 2>&1; do
		if "$probe_failed" >/dev/null 2>&1; then
			failure_dump "template-failed"
			fail "$description (template entered Failed)"
		fi
		attempt=$((attempt + 1))
		if [[ "$attempt" -ge "$attempts" ]]; then
			failure_dump "template-timeout"
			fail "$description (after $attempts attempts)"
		fi
		sleep 2
	done
	pass "$description"
}

# Template build via the CLI (server /templates API behind it): the row is
# projected onto a SandboxTemplate CRD; the build runs in fast-sandbox, so
# the builder image must be in the cluster.

_template_phase() {
	osb_api template get "$TEMPLATE_ID" -o json 2>/dev/null | jq -r '.status.phase // empty'
}

template_succeeded() {
	[[ "$(_template_phase)" == "Succeeded" ]]
}

template_failed() {
	local phase message
	phase="$(_template_phase)"
	[[ "$phase" == "Failed" ]] || return 1
	message="$(osb_api template get "$TEMPLATE_ID" -o json 2>/dev/null | jq -r '.status.message // empty')"
	log "template Failed: ${message:-<no message>}"
	return 0
}

template_up() {
	log "building the sandboxtemplate-builder image"
	# shellcheck disable=SC2086
	docker build ${DOCKER_BUILD_FLAGS:-} --quiet -t "$IMG_BUILDER" \
		-f "$FSB_DIR/build/Dockerfile.sandboxtemplate-builder" "$FSB_DIR" >/dev/null \
		|| die "sandboxtemplate-builder image build failed"
	kind load docker-image "$IMG_BUILDER" --name "$KIND_CLUSTER" >/dev/null
	local created
	local -a tmpl_args=(
		template create
		--image "$SBX_IMAGE"
		--publish "s3://$RUSTFS_BUCKET/publish"
		--format native
		--resource cpu=1 --resource memory=512Mi --resource disk=2Gi
		--warmup-seconds 15
		--metadata origin=fast-sandbox-env
	)
	log "verify: creating the golden-image template via the opensandbox CLI (image=$SBX_IMAGE)"
	created="$(osb_api "${tmpl_args[@]}" -o json 2>/dev/null)" \
		|| fail "template create failed against $SERVER_URL: $(osb_api "${tmpl_args[@]}" 2>&1 >/dev/null | head -c 400)"
	TEMPLATE_ID="$(printf '%s' "$created" | jq -r '.template_id')"
	printf '%s' "$TEMPLATE_ID" > "$WORK/template-id"
	[[ -n "$TEMPLATE_ID" && "$TEMPLATE_ID" != "null" ]] || fail "template create response carried no templateId"
	log "template id=$TEMPLATE_ID"
	wait_succeeded "template phase=Succeeded" 300 template_succeeded template_failed
	local manifest_ref
	manifest_ref="$(osb_api template get "$TEMPLATE_ID" -o json | jq -r '.status.manifest_ref // empty')"
	[[ -n "$manifest_ref" ]] || fail "template manifestRef is empty"
	log "template manifestRef: $manifest_ref"
	pass "SandboxTemplate Succeeded + artifacts published (via opensandbox CLI)"
}

# --- stage: SandboxPool (egress attached, P2P spread) --------------------------------------------

pool_pods() {
	kubectl -n "$RESOURCE_NS" get pods \
		-l "app=sandbox-fastlet,fast-sandbox.io/pool=$POOL_NAME" \
		-o jsonpath='{.items[*].metadata.name}' 2>/dev/null
}

first_pool_pod() {
	kubectl -n "$RESOURCE_NS" get pods \
		-l "app=sandbox-fastlet,fast-sandbox.io/pool=$POOL_NAME" \
		-o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

fastlet_pods_ready() {
	local ready=0 pod
	for pod in $(pool_pods); do
		if kubectl -n "$RESOURCE_NS" get pod "$pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q True; then
			ready=$((ready + 1))
		fi
	done
	[[ "$ready" -ge "$POOL_MIN" ]]
}

egress_containers_ready() {
	local pods pod
	pods="$(pool_pods)"
	[[ -n "$pods" ]] || return 1
	for pod in $pods; do
		kubectl -n "$RESOURCE_NS" get pod "$pod" -o jsonpath='{range .status.containerStatuses[*]}{.name}{"="}{.ready}{" "}{end}' 2>/dev/null \
			| grep -q 'egress=true' || return 1
	done
}

# GET /_fastlet/v1/actions/status must echo the shared apiVersion, ready=true
# and a non-empty instanceId; the handler binds Pod loopback only, so the
# probe runs inside the egress container.
egress_status_ready() {
	local pod out
	pod="$(first_pool_pod)"
	[[ -n "$pod" ]] || return 1
	out="$(kubectl -n "$RESOURCE_NS" exec "pod/$pod" -c egress -- \
		curl -fsS -m 5 "http://127.0.0.1:18080/_fastlet/v1/actions/status" 2>/dev/null)" || return 1
	[[ "$out" == *'"apiVersion":"sandbox.fast.io/actions/v1"'* && "$out" == *'"ready":true'* && "$out" == *'"instanceId":'* ]]
}

pool_status_ready() {
	local ready
	ready="$(kubectl_get "sandboxpool/$POOL_NAME" '{.status.readyPods}' 2>/dev/null || true)"
	[[ "$ready" =~ ^[0-9]+$ ]] && (( ready >= POOL_MIN ))
}

pool_condition_true() { # condition-type
	[[ "$(kubectl_get "sandboxpool/$POOL_NAME" "{.status.conditions[?(@.type==\"$1\")].status}" 2>/dev/null)" == "True" ]]
}

warm_images_ready() {
	kubectl -n "$RESOURCE_NS" get sandboxpool "$POOL_NAME" -o jsonpath='{.status.warmImages[*].cachedFastlets}' 2>/dev/null | grep -qv '^0*$'
}

render_pool() { # > $GEN_DIR/firecracker-egress-pool.yaml
	local src="$MANIFESTS_DIR/pool/firecracker-egress-pool.yaml" out="$GEN_DIR/firecracker-egress-pool.yaml"
	mkdir -p "$GEN_DIR"
	# Quoted tokens in the template keep rendered scalars' natural types
	# (poolMin stays an integer); awk for sed portability.
	awk -v fastlet="$IMG_FASTLET" -v egress="$IMG_EGRESS" \
		-v pool_min="$POOL_MIN" -v pool_max="$POOL_MAX" \
		-v max_per_pod="$MAX_SANDBOXES_PER_POD" \
		-v warm="$WARM_IMAGES" -v image="$TEMPLATE_ID" '
		{ gsub(/"@FASTLET_IMAGE@"/, fastlet)
		  gsub(/"@EGRESS_IMAGE@"/, egress)
		  gsub(/"@POOL_MIN@"/, pool_min)
		  gsub(/"@POOL_MAX@"/, pool_max)
		  gsub(/maxSandboxesPerPod: 5/, "maxSandboxesPerPod: " max_per_pod) }
		/^# @WARM_IMAGES@$/ {
			if (warm == "1") printf "  warmImages:\n  - %s\n", image
			next }
		{ print }
	' "$src" > "$out"
	# Leftover-token guard: match only value positions (key: ...@T@...),
	# never the header comments that document the tokens themselves.
	if grep -Eq '^[[:space:]]*[A-Za-z][A-Za-z0-9]*:.*@[A-Z_]+@' "$out"; then
		die "unrendered token left in $out"
	fi
}

pool_up() {
	render_pool
	log "applying SandboxPool $POOL_NAME (runtime=firecracker, egress attached, poolMin=$POOL_MIN)"
	kubectl apply -f "$GEN_DIR/firecracker-egress-pool.yaml" >/dev/null
	wait_for "fastlet pods Ready (poolMin=$POOL_MIN)" 300 fastlet_pods_ready
	wait_for "egress container ready in every fastlet pod" 180 egress_containers_ready
	wait_for "pool condition RuntimeReady=True" 120 pool_condition_true RuntimeReady
	wait_for "pool condition InfraReady=True" 120 pool_condition_true InfraReady
	wait_for "egress actions endpoint answering (/_fastlet/v1/actions/status)" 60 egress_status_ready
	if [[ "$WARM_IMAGES" == "1" ]]; then
		wait_for "pool warmImages Ready" 300 warm_images_ready
		p2p_evidence "warm preheat"
		pass "fastlet Running + warmImages Ready (P2P evidence captured)"
	else
		pass "fastlet Running, on-demand pull (default: first sandbox pulls through DART)"
	fi
}

# Assert the P2P outcome from DART block counters: the artifact set is
# pulled ~once per 4MiB block from the origin cluster-wide, and extra nodes
# must be fed by peers, not the origin.
p2p_evidence() { # description
	local description="$1"
	local pods pod manifest_ref manifest_key build_dir expected_blocks=0 stat_json
	local origin_total=0 peer_total=0 cache_total=0 size source value active_nodes=0 node_total
	manifest_ref="$(osb_api template get "$TEMPLATE_ID" -o json 2>/dev/null | jq -r '.status.manifest_ref // empty')"
	manifest_key="${manifest_ref#s3://$RUSTFS_BUCKET/}"
	build_dir="$(dirname "$manifest_key")"
	local object
	for object in rootfs.ext4 vmstate.snap memory.snap; do
		stat_json="$(rc stat --json "chain/$RUSTFS_BUCKET/$build_dir/$object" 2>&1)" \
			|| die "rc stat failed for published $object (publish incomplete?): $stat_json"
		size="$(jq -er '.size_bytes | numbers' <<<"$stat_json" 2>/dev/null)" \
			|| die "rc stat returned no numeric size_bytes for published $object"
		expected_blocks=$((expected_blocks + (size + 4194303) / 4194304))
	done
	pods="$(runtime_pods)"
	for pod in $pods; do
		node_total=0
		while read -r source value; do
			case "$source" in
				origin) origin_total=$((origin_total + value)); node_total=$((node_total + value)) ;;
				peer) peer_total=$((peer_total + value)); node_total=$((node_total + value)) ;;
				cache) cache_total=$((cache_total + value)); node_total=$((node_total + value)) ;;
			esac
		done < <(dart_source_counters "$pod")
		[[ "$node_total" -gt 0 ]] && active_nodes=$((active_nodes + 1))
	done
	log "p2p evidence ($description): expected origin=$expected_blocks blocks; cluster origin=$origin_total peer=$peer_total cache=$cache_total active-nodes=$active_nodes"
	[[ "$origin_total" -ge "$expected_blocks" ]] || fail "cluster origin $origin_total < expected $expected_blocks blocks"
	[[ "$origin_total" -le $((expected_blocks + 4)) ]] \
		|| fail "origin amplified: $origin_total > $((expected_blocks + 4)): pulls were not deduplicated by DART"
	if [[ "$active_nodes" -ge 2 ]]; then
		[[ "$peer_total" -gt 0 ]] || fail "no peer traffic across $active_nodes nodes: the second node was not served by the peer"
		pass "P2P evidence ($description): origin ~1 fetch per block (cluster=$origin_total/$expected_blocks), peer=$peer_total, nodes=$active_nodes"
	else
		pass "P2P evidence ($description): origin ~1 fetch per block (cluster=$origin_total/$expected_blocks) on $active_nodes node (no peer needed)"
	fi
}

dart_source_counters() { # pod -> "<source> <value>" lines
	local pod="$1"
	kubectl exec -n "$NS" "$pod" -- sh -c 'curl -fsS --noproxy "*" http://127.0.0.1:8147/metrics' 2>/dev/null \
		| awk '/^dart_block_source_total\{source="(cache|peer|origin)"\}/ {
			match($0, /source="[^"]+"/); s = substr($0, RSTART + 8, RLENGTH - 9)
			match($0, /} [0-9]+$/); print s, substr($0, RSTART + 2)
		}'
}

# --- stage: idle-pause Redis (OSEP-0024 profile) --------------------------------

redis_up() {
	# The sweeper connects at startup, so Redis must precede the server.
	[[ "$IDLE_PAUSE" == "1" ]] || { log "idle-pause profile off (IDLE_PAUSE=0); skipping Redis"; rm -f "$WORK/idle-pause"; return 0; }
	touch "$WORK/idle-pause"
	mkdir -p "$GEN_DIR"
	sed "s|image: redis:7-alpine|image: $REDIS_IMAGE|" \
		"$MANIFESTS_DIR/idle-pause/redis.yaml" > "$GEN_DIR/idle-pause-redis.yaml"
	kubectl apply -n "$OSB_NS" -f "$GEN_DIR/idle-pause-redis.yaml" >/dev/null
	wait_for "idle-pause Redis deployment ready" 120 \
		kubectl -n "$OSB_NS" rollout status deploy/idle-pause-redis --timeout=10s
	pass "idle-pause Redis up ($REDIS_DSN)"
}

# --- stage: OpenSandbox server + ingress gateway --------------------------------

# Per-workdir key (not per-run): re-applies must keep old routes verifiable.
osb_signing_key() {
	if [[ ! -s "$SIGNING_KEY_FILE" ]]; then
		openssl rand -base64 32 | tr -d '\n' > "$SIGNING_KEY_FILE"
	fi
	cat "$SIGNING_KEY_FILE"
}

# Server config.toml (fsb runtime) with workdir tokens; the gateway [ingress]
# block is appended by charts/server from server.gateway.* values.
render_server_config() { # > $GEN_DIR/osb-server-config.toml
	mkdir -p "$GEN_DIR"
	awk -v api_key="$SERVER_API_KEY" \
		-v fastpath="$FASTPATH_ENDPOINT" -v fsb_ns="$RESOURCE_NS" -v pool="$POOL_NAME" \
		-v execd="$EXECD" '
		{ gsub(/@SERVER_API_KEY@/, api_key)
		  gsub(/@SIGNING_KEY@/, signing_key)
		  gsub(/@FASTPATH_ENDPOINT@/, fastpath)
		  gsub(/@FSB_NAMESPACE@/, fsb_ns)
		  gsub(/@POOL_NAME@/, pool)
		  gsub(/@EXECD_IMAGE@/, execd)
		  gsub(/@GATEWAY_ADDRESS@/, gateway)
		  print }
	' <<'TOML' > "$GEN_DIR/osb-server-config.toml"
[server]
host = "0.0.0.0"
port = 80
api_key = "@SERVER_API_KEY@"

[log]
level = "INFO"

[runtime]
type = "kubernetes"
execd_image = "@EXECD_IMAGE@"

[kubernetes]
# One block for CR reads + fsb settings; sandboxes live in the pool's
# namespace (poolRef resolves) and get the execd image injected by the server.
namespace = "@FSB_NAMESPACE@"
fastpath_endpoint = "@FASTPATH_ENDPOINT@"
fastpath_resource_pool = "@POOL_NAME@"
fastpath_wait_ready_seconds = 30.0
template_s3_publish_secret = "sandbox-oss-credentials"
TOML
	if [[ "$IDLE_PAUSE" == "1" ]]; then
		# Dotted keys nest the redis sub-table.
		cat >> "$GEN_DIR/osb-server-config.toml" <<TOML

[automation.idle_pause]
enabled = true
sweep_interval_seconds = 5
activity_ttl_seconds = 1800
redis.dsn = "$REDIS_DSN"
redis.lock_ttl_seconds = 30
TOML
	fi
	if grep -Eq '@[A-Z_]+@' "$GEN_DIR/osb-server-config.toml"; then
		die "unrendered token left in $GEN_DIR/osb-server-config.toml"
	fi
}

opensandbox_up() {
	kind load docker-image "$IMG_SERVER" --name "$KIND_CLUSTER" >/dev/null
	kind load docker-image "$IMG_INGRESS" --name "$KIND_CLUSTER" >/dev/null
	render_server_config
	apply_ns "$OSB_NS"
	# charts/server has the fsb RBAC built in; the config carries the wiring.
	helm_render opensandbox-server "$OSB_ROOT/manifests/charts/server" "$OSB_NS" \
		"$GEN_DIR/osb-server.yaml" \
		--set server.image.repository="$(image_repo "$IMG_SERVER")" \
		--set server.image.tag="$(image_tag "$IMG_SERVER")" \
		--set server.service.type=NodePort \
		--set server.service.nodePort="$SERVER_NODEPORT" \
		--set server.resources.requests.cpu=250m \
		--set server.resources.requests.memory=512Mi \
		--set server.resources.limits.cpu=1 \
		--set server.resources.limits.memory=2Gi \
		--set-file configToml="$GEN_DIR/osb-server-config.toml" \
		--set server.gateway.enabled=true \
		--set server.gateway.host="$GATEWAY_ADDRESS" \
		--set server.gateway.gatewayRouteMode=header \
		--set server.gateway.secureAccess.activeKey=a \
		--set "server.gateway.secureAccess.keys[0].key_id=a" \
		--set "server.gateway.secureAccess.keys[0].key=$(osb_signing_key)"
		kubectl apply -f "$GEN_DIR/osb-server.yaml" >/dev/null
	# fast-sandbox provider via FastPath, same signing key as the server.
	local gateway_idle_args=()
	if [[ "$IDLE_PAUSE" == "1" ]]; then
		gateway_idle_args=(
			--set gateway.activity.enabled=true
			--set gateway.activity.redisDsn="$REDIS_DSN"
			--set gateway.activity.minInterval=5s
			--set gateway.activity.ttlSeconds=1800
			--set gateway.wake.enabled=true
			--set gateway.wake.parkBudget="${IDLE_PAUSE_PARK_BUDGET:-5s}"
		)
	fi
	helm_render opensandbox-ingress-gateway "$OSB_ROOT/manifests/charts/ingress-gateway" "$OSB_NS" \
		"$GEN_DIR/osb-ingress-gateway.yaml" \
		--set gateway.image.repository="$(image_repo "$IMG_INGRESS")" \
		--set gateway.image.tag="$(image_tag "$IMG_INGRESS")" \
		--set gateway.replicaCount=1 \
		--set gateway.providerType=fast-sandbox \
		--set gateway.dataplaneNamespace="$NS" \
		--set gateway.fastpathEndpoint="$FASTPATH_ENDPOINT" \
		--set "gateway.secureAccess.keys[0].key_id=a" \
		--set "gateway.secureAccess.keys[0].key=$(osb_signing_key)" \
		--set gateway.service.type=NodePort \
		--set gateway.service.nodePort="$GATEWAY_NODEPORT" \
		--set gateway.resources.requests.cpu=100m \
		--set gateway.resources.requests.memory=128Mi \
		--set gateway.resources.limits.cpu=1 \
		--set gateway.resources.limits.memory=1Gi \
		"${gateway_idle_args[@]}"
	kubectl apply -f "$GEN_DIR/osb-ingress-gateway.yaml" >/dev/null
	wait_for "server deployment ready" 180 \
		kubectl -n "$OSB_NS" rollout status deploy/opensandbox-server --timeout=10s
	wait_for "ingress gateway deployment ready" 180 \
		kubectl -n "$OSB_NS" rollout status deploy/opensandbox-ingress-gateway --timeout=10s
	# A ready gateway proves FastPath reachability: it fails startup without
	# the gRPC connection.
	wait_for "server /health on 127.0.0.1:$SERVER_HOST_PORT" 60 \
		curl -fsS -m 5 "$SERVER_URL/health"
	wait_for "gateway /status.ok on $GATEWAY_ADDRESS" 60 \
		curl -fsS -m 5 --noproxy "*" "$GATEWAY_URL/status.ok"
	pass "server + ingress gateway up (fsb runtime, gateway routes signed with key 'a')"
}
dart_metrics_summary() {
	local pods pod node metrics
	pods="$(runtime_pods 2>/dev/null || true)"
	[[ -n "$pods" ]] || { echo "  (no agent pods)"; return 0; }
	for pod in $pods; do
		node="$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.nodeName}' 2>/dev/null)"
		metrics="$(kubectl exec -n "$NS" "$pod" -- sh -c 'curl -fsS --noproxy "*" http://127.0.0.1:8147/metrics' 2>/dev/null || true)"
		echo "  $node:"
		if [[ -z "$metrics" ]]; then
			echo "    (DART metrics unreachable)"
			continue
		fi
		printf '%s\n' "$metrics" | grep -E '^dart_block_source_total\{source="(cache|peer|origin)"\}' \
			| sed 's/^/    /' || true
	done
}

status() {
	log "status: RustFS"
	docker ps --filter "name=$RUSTFS_CONTAINER" --format '{{.Names}} {{.Status}}' 2>/dev/null || true
	echo
	log "status: kind cluster / nodes"
	if kind get clusters 2>/dev/null | grep -x "$KIND_CLUSTER" >/dev/null; then
		kubectl get nodes -o wide
	else
		log "kind cluster $KIND_CLUSTER: down"
		return 0
	fi
	echo
	log "status: pods ($NS)"
	if [[ "$IDLE_PAUSE" == "1" ]]; then
		log "status: idle-pause Redis ($OSB_NS)"
		kubectl -n "$OSB_NS" get deploy,svc -l app=idle-pause-redis -o wide 2>/dev/null || true
		echo
	fi
	kubectl -n "$NS" get pods -o wide
	kubectl -n "$RESOURCE_NS" get pods -o wide
	echo
	log "status: SandboxPool"
	kubectl -n "$RESOURCE_NS" get sandboxpool \
		-o custom-columns='NAME:.metadata.name,RUNTIME:.spec.runtime,READY:.status.readyPods,CAPACITY:.spec.capacity.poolMin,WARM_IMAGES:.status.warmImages' 2>/dev/null || true
	echo
	log "status: fastlet pods (egress sidecar)"
	kubectl -n "$RESOURCE_NS" get pods -l app=sandbox-fastlet \
		-o custom-columns='NAME:.metadata.name,NODE:.spec.nodeName,CONTAINERS:.status.containerStatuses[*].name,READY:.status.containerStatuses[*].ready' 2>/dev/null || true
	echo
	log "status: DART P2P (block_source cache/peer/origin per node)"
	dart_metrics_summary || true
	echo
	log "status: OpenSandbox ($OSB_NS)"
	if kubectl get namespace "$OSB_NS" >/dev/null 2>&1; then
		kubectl -n "$OSB_NS" get pods -o wide
		printf '  server health:  %s\n' "$(curl -fsS -m 5 "$SERVER_URL/health" >/dev/null 2>&1 && echo OK || echo unreachable)"
		printf '  gateway health: %s\n' "$(curl -fsS -m 5 "$GATEWAY_URL/status.ok" >/dev/null 2>&1 && echo OK || echo unreachable)"
		printf '  server URL:     %s (header OPEN-SANDBOX-API-KEY: %s)\n' "$SERVER_URL" "$SERVER_API_KEY"
		printf '  gateway URL:    %s (header routing, signed f1.* scopes)\n' "$GATEWAY_URL"
	else
		echo "  (not deployed)"
	fi
}

env_summary() {
	highlight "== environment summary =="
	printf '  %-22s %s\n' "kind cluster" "$KIND_CLUSTER ($(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ') nodes)"
	printf '  %-22s %s\n' "fast-sandbox" "pinned $(git -C "$FSB_DIR" rev-parse --short HEAD 2>/dev/null || echo "$FSB_COMMIT") ($FSB_DIR)"
	printf '  %-22s %s\n' "RustFS endpoint" "$RUSTFS_ENDPOINT"
	printf '  %-22s %s\n' "pool" "$POOL_NAME (runtime=firecracker, poolMin=$POOL_MIN, egress=$IMG_EGRESS)"
	printf '  %-22s %s\n' "P2P" "DART daemons=$(printf '%s' "$(runtime_pods)" | wc -w | tr -d ' ') (on-demand pulls: cache -> peer -> origin)"
	printf '  %-22s %s\n' "template" "${TEMPLATE_ID:-n/a} ($(if [[ -n "$TEMPLATE_ID" ]]; then _template_phase || echo unknown; else echo "not built"; fi))"
	printf '  %-22s %s\n' "StateRoot fs" "$(findmnt -no FSTYPE "$XFS_MOUNT_POINT" 2>/dev/null || echo 'plain directory (full copy per sandbox)')"
	printf '  %-22s %s\n' "server" "$IMG_SERVER -> $SERVER_URL (fsb runtime)"
	printf '  %-22s %s\n' "ingress gateway" "$IMG_INGRESS -> $GATEWAY_URL (fsb provider, header mode)"
	printf '  %-22s %s\n' "fastpath" "$FASTPATH_ENDPOINT"
	printf '  %-22s %s\n' "logs" "$LOGS_DIR"
}

# --- down ------------------------------------------------------------------------------------

down() {
	log "down: teardown"
	if kind get clusters 2>/dev/null | grep -x "$KIND_CLUSTER" >/dev/null; then
		kind delete cluster --name "$KIND_CLUSTER" > "$LOGS_DIR/kind-delete.log" 2>&1 || true
	fi
	[[ -z "$(kind get clusters 2>/dev/null | grep -x "$KIND_CLUSTER" || true)" ]] \
		|| fail "kind cluster $KIND_CLUSTER still exists after delete"
	docker rm -f "$RUSTFS_CONTAINER" >/dev/null 2>&1 || true
	[[ -z "$(docker ps -a --filter "name=$RUSTFS_CONTAINER" --format '{{.Names}}' || true)" ]] \
		|| fail "RustFS container still present"
	# Server/gateway die with the cluster; only the signing key outlives it.
	rm -f "$WORK/agent-registry.json" "$SIGNING_KEY_FILE"
	rm -rf "$GEN_DIR" "$FSB_GEN_DIR"
	# A stale profile marker would let idle-e2e run against a stack whose
	# Redis/sweeper are gone.
	rm -f "$WORK/idle-pause"
	# RustFS data is owned by UID/GID 10001; leftovers pollute the host and
	# later docker build contexts.
	sudo_ rm -rf "$RUSTFS_DATA"
	sudo_ rm -rf "$RC_CONFIG_DIR"
	sysctl_restore
	stateroot_xfs_down
	# A committed DART cache is FINAL (never refreshed): purge it, or a
	# rebuilt SandboxTemplate stays ignored when the StateRoot survives.
	stateroot_scrub
	pass "host cleanup complete"
}

# --- bring-up pipeline --------------------------------------------------------------

# Provisioning stages only (no verify stages): the entry script chains these
# with the verify/*.sh suites so `up` reports one unified stage summary.
env_up_stages() {
	run_stage "preflight + tooling" preflight
	run_stage "opensandbox CLI (osb, latest from PyPI)" ensure_osb
	run_stage "sysctl (fs.inotify)" sysctl_set
	run_stage "fast-sandbox checkout @ pinned commit" ensure_fsb
	run_stage "build images (fast-sandbox + OpenSandbox)" build_images
	run_stage "XFS StateRoot (reflink)" stateroot_xfs_up
	run_stage "render kind config" render_kind_config
	run_stage "kind cluster (KVM passthrough + labels)" kind_up
	run_stage "RustFS + bucket" rustfs_up
	run_stage "RustFS endpoint (kind network)" resolve_rustfs_endpoint
	run_stage "CRDs + control plane" control_plane_up
	run_stage "credentials (publish/pull)" credentials_up
	run_stage "firecracker runtime readiness + DART (P2P)" runtime_up
	run_stage "idle-pause Redis (OSEP-0024 profile)" redis_up
	run_stage "OpenSandbox server + ingress gateway" opensandbox_up
	run_stage "SandboxTemplate build (opensandbox CLI)" template_up
	run_stage "SandboxPool $POOL_NAME (egress + P2P)" pool_up
}

# Shared `up` prelude: output tee'd into $WORK/run.log, environment
# snapshot, and leftover cleanup. Used by the standalone env_up and by the
# entry script (which chains the verify stages after env_up_stages).
env_up_prelude() {
	exec > >(tee -a "$WORK/run.log") 2>&1
	log "=== fast-sandbox-env up ($(date -u +%FT%TZ)) ==="
	{
		echo "environment snapshot ($(date -u +%FT%TZ))"
		command -v kind >/dev/null && kind --version
		kubectl version --client 2>/dev/null | head -1
		go version
		docker --version
		echo "cluster=$KIND_CLUSTER single=$KIND_SINGLE rustfs=$RUSTFS_IMAGE port=$RUSTFS_PORT bucket=$RUSTFS_BUCKET"
		echo "sbxImage=$SBX_IMAGE execd=$EXECD warmImages=$WARM_IMAGES"
		echo "pool=$POOL_NAME poolMin=$POOL_MIN egress=$IMG_EGRESS"
		echo "server=$IMG_SERVER ingress=$IMG_INGRESS fastpath=$FASTPATH_ENDPOINT"
		echo "images: controller=$IMG_CONTROLLER runtime=$IMG_RUNTIME"
	} > "$LOGS_DIR/environment.txt" 2>&1 || true
	if [[ -n "$(kind get clusters 2>/dev/null | grep -x "$KIND_CLUSTER" || true)" ]] \
		|| docker ps -a --format '{{.Names}}' | grep -qx "$RUSTFS_CONTAINER"; then
		if [[ "$SKIP_LEFTOVER_CLEAN" == 1 ]]; then
			log "leftover resources detected; aborting (SKIP_LEFTOVER_CLEAN=1). Run 'integration.sh down' first"
			exit 1
		fi
		log "leftover resources detected; cleaning and rebuilding"
		down
	fi
}

# Standalone `up`: provision everything, no verify stages.
env_up() {
	env_up_prelude
	trap 'on_error up' ERR
	env_up_stages
	trap - ERR
	stage_summary
	env_summary
	highlight "== up complete: server=$SERVER_URL (header OPEN-SANDBOX-API-KEY: $SERVER_API_KEY), gateway=$GATEWAY_URL =="
}

env_usage() {
	cat <<'EOUT'
usage: env.sh {up|down|status|pool}

  up       provision the environment (no verify stages): fast-sandbox@pinned-commit
           images, two-node kind cluster (KVM), RustFS, control plane,
           firecracker runtime readiness + DART (P2P), SandboxTemplate golden
           image, firecracker-egress-pool (egress attached), the source-built
           OpenSandbox server + ingress gateway
  pool     re-apply only the SandboxPool (after editing manifests/pool/)
  status   nodes / pods / pool / DART P2P counters / RustFS / OpenSandbox health
  down     teardown: kind cluster + RustFS + sysctl + XFS StateRoot + caches

  The entry script (integration.sh) chains `up` with the verify stages;
  see its header for the full action set and environment overrides.
EOUT
	exit 1
}

# Standalone dispatch (skipped when sourced by the entry script).
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	case "${1:-}" in
		up) env_up ;;
		pool)
			exec > >(tee -a "$WORK/run.log") 2>&1
			kind get clusters 2>/dev/null | grep -x "$KIND_CLUSTER" >/dev/null \
				|| die "cluster $KIND_CLUSTER is not up (run up first)"
			trap 'on_error pool' ERR
			run_stage "SandboxPool $POOL_NAME (egress + P2P)" pool_up
			trap - ERR
			env_summary
			;;
		status) status ;;
		down) down ;;
		*) env_usage ;;
	esac
fi
