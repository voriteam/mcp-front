# The image no longer bakes vori/config.json; the gateway config now lives in
# backend at services/mcp-front/k8s/base/config.json (mounted as a ConfigMap in
# prod). Mount it explicitly here and point mcp-front at it.
BACKEND="${BACKEND:-$HOME/workspace/backend}"

docker container rm -f mcp-front
docker run -p 8080:8080 \
  --env-file .env \
  -v "$HOME/.config/gcloud/application_default_credentials.json:/tmp/adc.json" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/adc.json \
  -v "$BACKEND/services/mcp-front/k8s/base/config.json:/config/config.json:ro" \
  --name mcp-front \
  mcp-front:latest -config /config/config.json
