echo "This builds a docker image for local execution"

echo "  building go linux image for ..."
CGO_ENABLED=0 GOOS=linux go build -o ./hexaOpa  cmd/hexaOpa/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./testBundleServer cmd/testBundleServer/main.go

echo "  building docker image..."
docker build --tag hexaopa .

echo "  Build complete. Execute using 'docker run hexaopa'"