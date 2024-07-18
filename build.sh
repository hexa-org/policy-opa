echo "\nHexaOPA builder utility\n"

tag="hexaopa"
test="N"
doPush="N"
platform=""
optString="mhtdcpn:"
multi="N"
while getopts ${optString} OPTION; do
  case "$OPTION" in
    t)
      test="Y"
      ;;
    n)
      tag=${OPTARG}
      echo "  ..using docker tag: $tag"
      ;;
    p)
      echo "  ..push to Docker Hub requested"
      doPush="Y"
      ;;
    c)
      echo "* Installing Hexa CLI"
      if ! command -v hexa &> /dev/null
      then
          go install github.com/hexa-org/policy-mapper/cmd/hexa@latest
          exit 1
      fi
      hexa help
      exit
      ;;

    m)
      echo " ..multi platform build selected"
      multi="Y"
      ;;
    *)
      echo "Usage: ./build.sh -b -t <tag> -p"
      echo "  -t         Performs build and test (default: build only)"
      echo "  -m         Build for multi-platform (requires docker with containerd configured)"
      echo "  -n <value> Builds the docker image with the specified tag name [hexaopa]"
      echo "  -p         Push the image to docker [default: not pushed]"
      echo "  -c         Check and install the Hexa CLI from github.com/hexa-org/policy-mapper"
      exit 1
  esac
done

echo "" # Newline

if [ "$test" = 'Y' ];then
    echo "* Building and running tests ..."
    go build ./...
    go test ./...
    echo ""
fi

echo "* Building go linux executables for docker ..."
CGO_ENABLED=0 GOOS=linux go build -o ./hexaOpa  cmd/hexaOpa/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./hexaBundleServer cmd/hexaBundleServer/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./hexaAuthZen cmd/hexaAuthZen/main.go
CGO_ENABLED=0 GOOS=linux go build -o ./hexaIndustriesDemo cmd/hexaIndustriesDemo/demo.go
echo ""

echo "* Building hexaKeyTool ..."
go build -o ./hexakey cmd/hexakey/main.go
echo ""

echo "* building docker container image ($tag)..."
echo "  - downloading latest chainguard platform image"
docker pull cgr.dev/chainguard/static:latest

if [ "$multi" = 'Y' ];then
   echo "  - performing multi platform build"
   docker build --platform=linux/amd64,linux/arm64 --tag "$tag" .
else
  echo "  - building for local platform"
  docker build --tag "$tag" .
fi


if [ "$doPush" = 'Y' ];then
    echo "  pushing to docker ..."
    docker push $tag
fi
echo "  Build complete. Execute using docker compose"