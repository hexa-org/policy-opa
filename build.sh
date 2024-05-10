echo "This builds a docker image for local execution"

tag="hexaopa"
test="N"
doPush="N"
optString="bpt:"
while getopts ${optString} OPTION; do
  case "$OPTION" in
    b)
      echo "Build and test requested."
      test="Y"
      ;;
    t)
      tag=${OPTARG}
      echo "Tag is $tag"
      ;;
    p)
      echo "Push requested."
      doPush="Y"
      ;;
    *)
      echo "Usage: ./build.sh -b -t <tag> -p"
      echo "  -b         Performs build and test (default: build only)"
      echo "  -t <value> Builds the docker image with the specified tag (default: hexaopa)"
      echo "  -p         Push the image to docker (default: not pushed)"
      exit 1
  esac
done

if [ "$test" = 'Y' ];then
    echo "  building and running tests ..."
    go build ./...
    go test ./...
fi

echo "  building go linux executables for docker ..."
CGO_ENABLED=0 GOOS=linux go build -o ./hexaOpa  cmd/hexaOpa/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./hexaBundleServer cmd/hexaBundleServer/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./hexaAuthZen cmd/hexaAuthZen/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./hexaIndustriesDemo cmd/hexaIndustriesDemo/demo.go

echo "  building hexaKeyTool ..."
go build -o ./hexaKeyTool cmd/hexaKeyTool/main.go

echo "  building docker container image ($tag)..."

docker build --tag $tag .

if [ "$doPush" = 'Y' ];then
    echo "  pushing to docker ..."
    docker push $tag
fi
echo "  Build complete. Execute using docker compose"