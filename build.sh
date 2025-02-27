echo "HexaOPA builder utility"
echo ""

tag="hexaopa"
test="N"
doPush="N"
aIn="amd64,arm64"
optString="amhtdcpn:"
multi="N"
while getopts ${optString} OPTION; do
  case "$OPTION" in
    a)
        aIn=${OPTARG}
        echo "  .. selecting arch: $aIn"
        ;;
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
      echo "  -a         Architectures (comma separated) [386|amd64|arm64|mips64|mips64le|ppc64|riscv64|s390x (default amd64]"
      echo "             Default is \"amd64,arm64\" when -m selected"
      echo "  -t         Performs build and test (default: build only)"
      echo "  -m         Build for multi-platform"
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

echo "* Building hexaKeyTool ..."
go build -o ./hexakey cmd/hexakey/main.go
echo ""

echo "* building docker container image ($tag)..."
echo "  - downloading latest chainguard platform image"
docker pull docker.io/chainguard/static:latest

if [ "$multi" = 'Y' ];then
   IFS=', ' read -ra archs <<< "$aIn"

   echo "Performing platform builds..."

   for arch in "${archs[@]}"
   do
     echo "----------------------------------------------------"
     echo "  - performing build for $arch"

     CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o ./hexaOpa  cmd/hexaOpa/main.go
     CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o ./hexaBundleServer cmd/hexaBundleServer/main.go
     CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o ./hexaAuthZen cmd/hexaAuthZen/main.go
     CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o ./hexaIndustriesDemo cmd/hexaIndustriesDemo/demo.go

     echo "  - building docker image $tag-$arch"
     docker buildx build --push --platform "linux/$arch" --provenance=true --sbom=true --tag "$tag-$arch" .
     echo ""
   done
else
  echo "  - building for local platform"
  CGO_ENABLED=0 GOOS=linux go build -o ./hexaOpa  cmd/hexaOpa/main.go
  CGO_ENABLED=0 GOOS=linux go build -o ./hexaBundleServer cmd/hexaBundleServer/main.go
  CGO_ENABLED=0 GOOS=linux go build -o ./hexaAuthZen cmd/hexaAuthZen/main.go
  CGO_ENABLED=0 GOOS=linux go build -o ./hexaIndustriesDemo cmd/hexaIndustriesDemo/demo.go

  echo "  - building docker image $tag-$arch"
  docker build --tag "$tag" .
fi


if [ "$doPush" = 'Y' ];then
    echo "  pushing to docker ..."
    docker push $tag
fi
echo "  Build complete. Execute using docker compose"