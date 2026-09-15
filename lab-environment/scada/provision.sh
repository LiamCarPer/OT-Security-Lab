#!/bin/sh
# Provision Scada-LTS with Modbus/TCP datasources and datapoints for the three
# PLCs, so the HMI genuinely polls the controllers over Modbus (no simulated
# master). Idempotent: existing XIDs are left untouched. Uses the Scada-LTS
# REST API (available since v2.7.5.2), which is the only IaC-friendly path -
# config rows are Java-serialized BLOBs, so direct SQL is not viable.
set -eu

BASE="${OT_SCADA_URL:-http://hmi:8080/Scada-LTS}"
USER="${OT_SCADA_USER:-admin}"
PASS="${OT_SCADA_PASS:-admin}"
# TARGETS format: "<plc name> <stage> <datasource xid> <host> <registers...>" per PLC
# The real OpenPLC controllers (programmed by plc-bootstrap). Reachable from the
# Supervisory zone through the gateway (conduit C1).
TARGETS="${OT_SCADA_TARGETS:-PLC-01 Intake DS_PLC1 172.21.0.10 0 1 5 6;PLC-02 Treatment DS_PLC2 172.21.0.11 0 1 2 5 6;PLC-03 Distribution DS_PLC3 172.21.0.12 0 1 2 5 6}"

SID=""

# logs go to stderr: stdout is reserved for command substitution return values
log() { echo "[SCADA-PROV] $*" >&2; }

# Authenticate and capture the JSESSIONID. curl's cookie jar is not reliably
# replayed across invocations in this image, so the session id is passed
# explicitly as a Cookie header.
auth() {
    SID=$(curl -s -D - -o /dev/null "$BASE/api/auth/$USER/$PASS" \
        | tr -d '\r' \
        | sed -n 's/^Set-Cookie: JSESSIONID=\([^;]*\).*/\1/p')
    [ -n "$SID" ]
}

wait_for_api() {
    i=0
    until auth; do
        i=$((i + 1))
        if [ "$i" -gt 120 ]; then
            log "timed out waiting for Scada-LTS at $BASE"
            exit 1
        fi
        sleep 5
    done
    log "authenticated against $BASE"
}

ensure_datasource() {
    xid=$1
    name=$2
    host=$3
    existing=$(curl -s -H "Cookie: JSESSIONID=$SID" "$BASE/api/datasource/getAll" \
        | jq -r --arg x "$xid" 'if type=="array" then (.[]? | select(.xid==$x) | .id) else empty end' \
        | head -1)
    payload=$(jq -nc --arg xid "$xid" --arg name "$name" --arg host "$host" '{
        xid:$xid, name:$name, type:3, enabled:true,
        connectionDescription:"common.default",
        updatePeriodType:1, updatePeriods:1,
        quantize:false, timeout:500, retries:2,
        contiguousBatches:false, createSlaveMonitorPoints:false,
        maxReadBitCount:2000, maxReadRegisterCount:125,
        maxWriteRegisterCount:120,
        transportType:"TCP", host:$host, port:502,
        encapsulated:false, createSocketMonitorPort:false
    }')
    if [ -n "$existing" ]; then
        # Update in place so a changed target host (OpenPLC <-> stand-in) applies.
        curl -s -o /dev/null -X PUT -H "Cookie: JSESSIONID=$SID" -H 'Content-Type: application/json' \
            "$BASE/api/datasource" -d "$(printf '%s' "$payload" | jq -c --argjson id "$existing" '. + {id:$id}')"
        log "datasource $xid updated (id=$existing, host=$host)"
        printf '%s' "$existing"
        return
    fi
    created=$(curl -s -H "Cookie: JSESSIONID=$SID" -H 'Content-Type: application/json' \
        -X POST "$BASE/api/datasource" -d "$payload")
    id=$(printf '%s' "$created" | jq -r '.id // empty')
    if [ -z "$id" ]; then
        log "ERROR creating datasource $xid: $created"
        exit 1
    fi
    log "created datasource $xid (id=$id, host=$host)"
    printf '%s' "$id"
}

ensure_datapoint() {
    dsid=$1
    dsxid=$2
    dsname=$3
    offset=$4
    xid="DP_${dsxid}_HR${offset}"
    exists=$(curl -s -H "Cookie: JSESSIONID=$SID" "$BASE/api/datapoint?xid=$xid" \
        | jq -e --arg x "$xid" 'if type=="array" then any(.[]?; .xid==$x) else (.xid==$x) end' >/dev/null 2>&1 && echo yes || echo no)
    if [ "$exists" = "yes" ]; then
        log "datapoint $xid exists"
        return
    fi
    curl -s -H "Cookie: JSESSIONID=$SID" -H 'Content-Type: application/json' \
        -X POST "$BASE/api/datapoint" -d "$(jq -nc \
            --arg xid "$xid" --arg name "${dsname} HR${offset}" \
            --argjson dsid "$dsid" --arg dsxid "$dsxid" --arg dsname "$dsname" \
            --argjson offset "$offset" '{
                xid:$xid, name:$name, description:null, enabled:true,
                dataSourceTypeId:3, dataSourceId:$dsid, deviceName:$dsname,
                pointLocator:{
                    dataSourceTypeId:"3", dataTypeId:2, settable:true,
                    range:3, modbusDataType:2, slaveId:1,
                    slaveMonitor:false, socketMonitor:false,
                    offset:$offset, bit:0, registerCount:0, charset:"ASCII",
                    settableOverride:true, multiplier:1.0, additive:0.0,
                    relinquishable:false
                },
                datasourceName:$dsname, dataSourceXid:$dsxid, typeId:3, settable:true
            }')" >/dev/null
    log "created datapoint $xid (HR $offset)"
}

# Enable point history (ON_CHANGE) so Scada-LTS records values for the mimic.
# The handler is addressed by numeric id: the xid route rejects the payload.
set_history() {
    xid=$1
    id=$(curl -s -H "Cookie: JSESSIONID=$SID" "$BASE/api/datapoint?xid=$xid" \
        | jq -r 'if type=="array" then (.[0].id // empty) else (.id // empty) end')
    if [ -z "$id" ]; then
        log "WARN could not resolve datapoint id for $xid"
        return
    fi
    curl -s -o /dev/null -X PUT -H "Cookie: JSESSIONID=$SID" -H 'Content-Type: application/json' \
        "$BASE/api/point_properties/updateProperties?id=$id" \
        -d '{"loggingType":1,"intervalLoggingPeriodType":1,"intervalLoggingPeriod":1,"intervalLoggingType":1,"purgeType":4,"purgePeriod":30,"purgeStrategy":1}'
    log "enabled history for $xid (id=$id)"
}

# Create the process mimic view scaffold. Graphical component placement is not
# exposed by the REST API, so the functional process mimic is the Grafana
# dashboard; this records the operator view in Scada-LTS.
ensure_view() {
    xid=$1
    name=$2
    existing=$(curl -s -H "Cookie: JSESSIONID=$SID" "$BASE/api/view/getByXid/$xid" \
        | jq -r '.xid // empty' 2>/dev/null)
    if [ -n "$existing" ]; then
        log "view $xid exists"
        return
    fi
    curl -s -o /dev/null -X POST -H "Cookie: JSESSIONID=$SID" -H 'Content-Type: application/json' \
        "$BASE/api/view/createView" \
        -d "{\"name\":\"$name\",\"xid\":\"$xid\",\"imagePath\":\"null.png\",\"size\":1}"
    log "created view $xid ($name)"
}

wait_for_api

echo "$TARGETS" | tr ';' '\n' | while read -r line; do
    [ -n "$line" ] || continue
    # shellcheck disable=SC2086
    set -- $line
    plc_name=$1
    short_name=$2
    ds_xid=$3
    host=$4
    shift 4
    ds_id=$(ensure_datasource "$ds_xid" "$plc_name $short_name" "$host")
    for offset in "$@"; do
        ensure_datapoint "$ds_id" "$ds_xid" "$plc_name" "$offset"
        set_history "DP_${ds_xid}_HR${offset}"
    done
done

ensure_view "VIEW_WATER" "Water Treatment"

touch /tmp/scada-provisioned
log "provisioning complete"
