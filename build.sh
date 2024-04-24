echo "This builds a docker image for local execution"

echo "  building go linux container image ..."
CGO_ENABLED=0 GOOS=linux go build -o ./hexaOpa  cmd/hexaOpa/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./hexaBundleServer cmd/hexaBundleServer/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./hexaAuthZen cmd/hexaAuthZen/main.go

echo "  building hexaKeyTool ..."
go build -o ./hexaKeyTool cmd/hexaKeyTool/main.go

echo "  building docker container image..."
docker build --tag hexaopa .

echo "  Build complete. Execute using docker compose"