![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Hexa Integration Support for Open Policy Agent (OPA)

This OPA Integration project extends support for Hexa IDQL Policy running inside an Open Policy Agent (OPA) server. 
Support includes new functionality for condition expressions new to IDQL
support. This integration includes:

* [Hexa rego policy](deployments/testBundleServer/resources/bundles/bundle/hexaPolicy.rego) to evaluate IDQL policy statements in an OPA Policy Agent.
* An OPA `hexaFilter` plugin enabling dynamic evaluation of IDQL Conditions.
* An extended OPA server `hexaOpa` which runs as a normal OPA server but with the `hexaFilter` extension.
* A client `opaTools` package which enables web applications to call OPA using a normalized query providing request and subject information for processing
* A `testBundleServer` which can be used to deploy policy to one or more OPA Agents.
* Supported as an integration with the [Hexa Mapper Project](https://github.com/hexa-org/policy-mapper).

## Introducing the Hexa OPA Server Integration

This integration of OPA follows the [Open Policy Agent extension mechanism](https://www.openpolicyagent.org/docs/latest/extensions/) to enable the processing if IDQL Condition clauses.
The HexaOpa server is a normal OPA server and can run any rego policy. A docker image is available at: [independentid/hexaopa](https://hub.docker.com/r/independentid/hexaopa).

Running `hexaOpa` works the same way as for opa. For more information, see the Open Policy Agent [Deployment Guide](https://www.openpolicyagent.org/docs/latest/deployments/).

### Building and Running Hexa OPA Locally

Prerequisites:
* [Go Lang 1.21](https://go.dev/doc/install)
* [Docker](https://docs.docker.com/engine/install/)
* [Git client](https://github.com/git-guides/install-git#)

With the above pre-requisites installed, clone the repository, change directory into the project and run the build.sh shell script. This will build a local docker image called hexaopa
```shell
git clone https://hexa-org/policy-mapper

cd policy-mapper

sh ./build.sh
```

Once the image is built, use [docker-compose.yml](docker-compose.yml) to start the testBundleServer and hexaOpa servers.
```shell
docker compose up
```
When the bundle-server container starts up, it will automatically generate self-signed TLS certificates to enable encrypted
communication between OPA and the test bundle server. If you wish to use your own certificates, update the docker-compose
environment variables to point to the appropriate directory/files.  See `.env` for a list of environment variables supported.

### Using HexaOpa In Docker-Compose or K8S

The HexaOpa image is available in the [independentid/hexaopa docker repository](https://hub.docker.com/r/independentid/hexaopa).  To use these images in a K8S configuration
or docker-compose, reference the image `independentid/hexaopa:latest`.


## Enabling Go Applications with OPA and IDQL
An OPA Client is simply an application (a policy enforcement point or PAP) that makes a request to an OPA server to request a policy decision.

To make a request, a client application may use the `opaTools` package to call PrepareInput to prepare an input object to pass to
OPA.
```go
func (w http.ResponseWriter, r *http.Request) {
    client := &http.Client{Timeout: time.Minute * 2}
    
    input := opaTools.PrepareInput(r)
    inputBytes, _ := json.Marshal(input)
    body := bytes.NewReader(inputBytes)
    req, err := http.NewRequest(http.MethodPost, "http://hexa-opa-server/v1/data/hexaPolicy", body)
    req.Header.Set("Authorization", someauth)  // authorization for OPA queries if needed
    
    resp, err := client.Do(req)
    . . .
}
```
In the above code, the input is prepared to pass to the OPA server. If you are using opaTools, the input will
look something like:
```json
{
    "req": {
        "ip": "127.0.0.1:65151",
        "protocol": "HTTP/1.1",
        "method": "GET",
        "path": "/testpath",
        "param": {
            "a": [
                "b"
            ],
            "c": [
                "d"
            ]
        },
        "header": {
            "Accept-Encoding": [
                "gzip"
            ],
            "Authorization": [
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwic3ViIjoiQmFzaWNCb2IiLCJhdWQiOlsidGVzdEF1ZGllbmNlIl0sImV4cCI6MTcxMDkwNzUyNywicm9sZXMiOiJiZWFyZXIgYWJjIn0.uBStTYLxJi5g0tZr_4RlixJmin6waDYOl4L_g7cGilU"
            ],
            "User-Agent": [
                "Go-http-client/1.1"
            ]
        },
        "time": "2024-03-19T21:00:29.825416-07:00"
    },
    "subject": {
        "roles": [
            "bearer",
            "abc"
        ],
        "expires": "2024-03-19T21:05:27-07:00",
        "type": "Bearer+JWT",
        "sub": "BasicBob",
        "iss": "testIssuer",
        "aud": [
            "testAudience"
        ],
        "iat": "0001-01-01T00:00:00Z",
        "nbf": "0001-01-01T00:00:00Z"
    }
}
```

When run against the example IDQL in /server/hexaFilter/test/bundle/bundle_test/data-V1.json, the following JSON
is returned:
```json
{
    "actionRights": [
        "TestIPMaskCanary/ietf:http:!PUT:/testpath*",
        "TestIPMaskCanary/ietf:http:GET:/testpath*",
        "TestIPMaskCanary/ietf:http:POST:/testpath*",
       . . .
        "TestJwtMember/ietf:http:POST:/testpath*",
        "TestJwtMember/ietf:http:PUT:/testpath*",
        "TestJwtRole/ietf:http:GET:/testpath*",
        "TestJwtRole/ietf:http:POST:/testpath*"
    ],
    "allow": true,
    "allowSet": [
        "TestIPMaskCanary",
        "TestIPMaskCanaryNotDelete",
        "TestIPMaskCanaryPOST",
        "TestJwtCanary",
        "TestJwtMember",
        "TestJwtRole"
    ]
}
```

In the above response, `allow` indicates the request is allowed. `allowSet` indicates all of the policies that
might apply to the subject (BasicBob), and `actionRights` indicates all of the policies and actions that are enabled. The
attributes actionRights and allowSet are provided to enable applications to control UI presentation such as what buttons 
to enable or disable.

In another example, the `hexaFilter` rego extension enables the ability to evaluate input structures provided by `client/opa/opaTools` request builder using
a condition clause in IDQL in the Hexa Rego script.

Example IDQL with Condition Statement:
```json
    {
      "id": "TestIPMaskCanaryPOST",
      "meta": {
        "version": "0.1",
        "date": "2021-08-01 21:32:44 UTC",
        "description": "Access enabling user self service for users with role",
        "applicationId": "CanaryBank1",
        "layer": "Browser"
      },
      "subject": {
        "type": "net",
        "providerId": "myTestIDP",
        "cidr" : "127.0.0.1/24"
      },
      "actions": [
        {
          "actionUri": "ietf:http:POST:/testpath*"
        },
        { 
          "actionUri": "ietf:http:GET:/testpath*"
        }
      ],
      "condition": {
        "rule": "req.ip sw 127 and req.method eq POST",
        "action": "allow"
      },
      "object": {
        "assetId": "CanaryProfileService",
        "pathSpec": "/testpath*"
      }
    }
```

The relevant enhancement in the above IDQL is:
```json
{
  "condition": {
    "rule": "req.ip sw 127 and req.method eq POST",
    "action": "allow"
  }
}
```
In this condition, the input values `req.ip` is evaluated to start with `127` and the `req.method` must equal `POST`.
Note that this example is a bit hypothetical since the "actions" already test permissible actions using the actionURI. The exmaple
provided is mainly to demonstrate that multiple conditions can be tested with and and or clauses as per the
[IDQL specification.](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md)
