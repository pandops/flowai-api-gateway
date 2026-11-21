#!/usr/bin/env bash
set -euo pipefail

postgres=docker.io/library/postgres@sha256:a85daf0dbd5e79586e850e3fe4b21b796799828ad015ce2166aeb98cc24da61c
nats=docker.io/library/nats@sha256:a7d440bf0240e664ed74fc17c70d616e6ff4bb9890dc26f7276589daedd1e196
mapping="flowai-agw-mapping-$(openssl rand -hex 12)"
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/api-gateway-integration.XXXXXXXX")
export FLOWAI_RESOURCE_LEDGER="$work/containers.jsonl"
touch "$FLOWAI_RESOURCE_LEDGER"
mapping_id=

cleanup() {
    local status=$? selector remaining
    if [[ -n "$mapping_id" ]]; then
        docker rm -f "$mapping_id" >/dev/null || status=1
    fi
    while IFS= read -r selector; do
        if ! [[ "$selector" =~ ^name=\^(flowai-agw-[0-9a-f]{24}|flowai-agw-nats-[0-9a-f]{16}|flowai-agw-mapping-[0-9a-f]{24})\$$ ]]; then
            status=1
            continue
        fi
        if ! remaining=$(docker ps -aq --filter "$selector") || [[ -n "$remaining" ]]; then
            echo "Fixture absence check failed for $selector" >&2
            status=1
        else
            echo "Verified fixture absence for $selector"
        fi
    done < <(python3 -c 'import json,sys; [print(json.loads(line)["selector"]) for line in open(sys.argv[1])]' "$FLOWAI_RESOURCE_LEDGER")
    rm -rf -- "$work"
    exit "$status"
}
trap cleanup EXIT

docker pull --platform linux/amd64 "$postgres"
docker pull --platform linux/amd64 "$nats"
selector="name=^$mapping\$"
test -z "$(docker ps -aq --filter "$selector")"
printf '{"kind":"containers","selector":"%s"}\n' "$selector" >> "$FLOWAI_RESOURCE_LEDGER"

# This database is exclusively owned by the baseline mapping concurrency case.
# The listener is on loopback and the container data lives in tmpfs.
password=$(openssl rand -hex 24)
mapping_id=$(docker run --detach --name "$mapping" --label flowai.api-gateway.test \
    --publish 127.0.0.1::5432 --tmpfs /var/lib/postgresql/data:rw \
    --env POSTGRES_USER=flowai --env "POSTGRES_PASSWORD=$password" \
    --env POSTGRES_DB=gateway_mapping "$postgres")
port=$(docker port "$mapping_id" 5432/tcp)
test "${port%:*}" = 127.0.0.1
timeout 60 bash -c 'until "$1" exec "$2" pg_isready -h 127.0.0.1 -U flowai -d gateway_mapping >/dev/null 2>&1; do sleep 1; done' _ docker "$mapping_id"
export FLOWAI_TEST_POSTGRES_URL="postgres://flowai:$password@127.0.0.1:${port##*:}/gateway_mapping?sslmode=disable"

test_status=0
if (( $# == 0 )); then
    set -- ./...
fi
go test -mod=readonly -count=1 -tags=integration -json "$@" || test_status=$?
python3 - "$FLOWAI_RESOURCE_LEDGER" <<'PY'
import json
import re
import sys

with open(sys.argv[1]) as ledger:
    records = [json.loads(line) for line in ledger]
assert len(records) == 3, records
for pattern in (r"flowai-agw-[0-9a-f]{24}", r"flowai-agw-nats-[0-9a-f]{16}",
                r"flowai-agw-mapping-[0-9a-f]{24}"):
    assert sum(record["kind"] == "containers" and
               re.fullmatch(r"name=\^" + pattern + r"\$", record["selector"]) is not None
               for record in records) == 1, records
PY
exit "$test_status"
