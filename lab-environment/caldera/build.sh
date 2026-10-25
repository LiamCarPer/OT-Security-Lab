#!/bin/sh
# Build the optional Caldera image. Kept separate from `docker compose build`
# so the default CI image-build job does not pay for this large build.
set -eu

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
VERSION="${OT_CALDERA_VERSION:-5.3.0}"
IMAGE="${OT_CALDERA_IMAGE:-ot-caldera:${VERSION}}"

echo "[caldera] building ${IMAGE} from Caldera ${VERSION}"
docker build --build-arg "CALDERA_VERSION=${VERSION}" -t "${IMAGE}" "${HERE}"
