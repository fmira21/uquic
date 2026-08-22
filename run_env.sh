set -euo pipefail
 
docker build -t uquic-dev -f Dockerfile.env .
 
docker run --rm -it \
  --name uquic-dev \
  --security-opt seccomp=unconfined \
  -v "$(pwd):/work" \
  -w /work \
  uquic-dev bash
