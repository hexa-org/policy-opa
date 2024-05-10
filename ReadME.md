![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Hexa Integration Support for Open Policy Agent (OPA)

This project provides support for running Hexa IDQL Policy on Open Policy Agent (OPA) servers. 
This integration includes:

* [Hexa Rego policy](deployments/hexaBundleServer/resources/bundles/bundle/hexaPolicy.rego) to evaluate IDQL policy statements in an OPA Policy Agent.
* An IDQL policy server, `hexaOpa`, which runs as a normal OPA server with the `hexaFilter` extension and `hexaPolicy.rego`.
* A policy information request builder, `opaTools`, that enables applications to call OPA using a query with normalized data for http request and subject information.
* A `hexaBundleServer` which is an HTTP based OPA Bundle Server that can be used to deploy policy to one or more OPA Agents.

The Hexa-OPA Project also includes two demonstration app showing integration of an application with IDQL based policy services:
* An implementation of the OpenID Authzen Interop called [hexaAuthZen](cmd/hexaAuthZen/README.md).
* A demo application called [Hexa Industries](cmd/hexaIndustriesDemo/README.md), showing a simple application calling the HexaOPA server for decisions based on IDQL, and, with policy provisioned using the [hexaBundleServer](cmd/hexaBundleServer).

## What is the HexaOPA Server?

This integration of [Hexa-Mapper](https://github.com/hexa-org/hexa-mapper) and Open Policy Agent ([OPA](https://www.openpolicyagent.org)) 
following the [Open Policy Agent extension mechanism](https://www.openpolicyagent.org/docs/latest/extensions/) to create an open source policy decision service based on IDQL policy.
The HexaOpa server is a normal OPA server and can run any rego policy. A docker image is available at: [independentid/hexaopa](https://hub.docker.com/r/independentid/hexaopa).

As with `OPA`, `hexaOpa` may be deployed as a sidecar or in other deployment patterns OPA Server. For more information, see the Open Policy Agent [Deployment Guide](https://www.openpolicyagent.org/docs/latest/deployments/).

### Building and Running Hexa OPA Locally

Prerequisites:
* [Go Lang 1.22](https://go.dev/doc/install)
* [Docker](https://docs.docker.com/engine/install/)
* [Git client](https://github.com/git-guides/install-git#)
* Hexa CLI Tool

To install the Hexa CLI tool you can clone the [Hexa-Mapper Project](https://github.com/hexa-org/policy-mapper), or run the following:

```shell
$ go install github.com/hexa-org/policy-mapper/cmd/hexa@latest
$ hexa help add opa
```

The Hexa command line interpreter tool allows you to retrieve and update IDQL OPA bundles to various types of servers including:
* HexaBundleServer (HTTP Service)
* GitHub Bundle Endpoint
* Amazon S3 Service
* Google Storage Service

With the above pre-requisites installed, clone the repository, change directory into the project and run the build.sh shell script. This will build a local docker image called hexaopa
```shell
$ git clone https://hexa-org/policy-mapper
$ cd policy-mapper
$ sh ./build.sh
```


Once the image is built, use [docker-compose.yml](docker-compose.yml) to start the hexaBundleServer and hexaOpa servers.
```shell
$ docker compose up
```
When the bundle-server container starts up, it will automatically generate self-signed TLS certificates to enable encrypted
communication between OPA and the test bundle server. If you wish to use your own certificates, update the docker-compose
environment variables to point to the appropriate directory/files.  See `.env` for a list of environment variables supported.

### Using HexaOpa In Docker-Compose or K8S

The HexaOpa image is available in the [independentid/hexaopa](https://hub.docker.com/r/independentid/hexaopa) docker repository.  To use these images in a K8S configuration
or docker-compose, reference the image `independentid/hexaopa:latest`.


## Enabling Go Applications with OPA and IDQL

An OPA Client is simply an application (a policy enforcement point or PAP) that makes a request to an OPA server to request a policy decision.

To make a request, a client application may use the `client/hexaOpaClient` package to call PrepareInput to prepare an input object to pass to
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

In the above response, `allow` indicates the request is allowed. `allowSet` indicates all the policies that
might apply to the subject (BasicBob), and `actionRights` indicates all the policies and actions that are enabled. The
attributes actionRights and allowSet are provided to enable applications to control UI presentation such as what buttons 
to enable or disable.

In another example, the `hexaFilter` rego extension enables the ability to evaluate input structures provided by `client/hexaOpaClient` request builder using
a condition clause in IDQL in the Hexa Rego script. In this example, in order for the request to be allowed, the user (subject) must be "BasicBob", and they must 
have a JWT authorization token with the role "abc" that is issued by "testIssuer". Additionally, the HTTP request must be either a `GET` or `POST` to the path `/testpath*`
where `*` is a wildcard to match any path beginning with `/testpath`.

Example IDQL with Condition Statement:
```json
{
  "meta": {
    "version": "0.6",
    "date": "2021-08-01 21:32:44 UTC",
    "description": "Test that allows jwt authenticated specific subject *and* has a role",
    "policyId": "TestJwtRole"
  },
  "subject": {
    "members" : ["user:BaSicBob"]
  },
  "actions": [
    {
      "actionUri": "ietf:http:POST:/testpath*"
    },
    {
      "actionUri": "ietf:http:GET:/testpath*"
    }
  ],
  "object": {
    "resource_id": "CanaryProfileService"
  },
  "condition": {
    "rule": "subject.type eq jwt and subject.iss eq testIssuer and subject.aud co testAudience and subject.roles co abc",
    "action": "allow"
  }
}
```

The relevant enhancement in the above IDQL is:
```json
"condition": {
  "rule": "subject.type eq jwt and subject.iss eq testIssuer and subject.aud co testAudience and subject.roles co abc",
  "action": "allow"
}
```
In the condition clause above, the authentication type is matched as `jwt`, the issuer and audience are also matched 
to the values `testIssuer` and `testAudience`, and finally the user is checked for the role "abc".
Note that this example is a bit hypothetical since the "actions" already test permissible actions using the actionURI. The example
provided is mainly to demonstrate that multiple conditions can be tested with `and` and `or` clauses as per the
[IDQL specification.](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md)

## Hexa Input for IDQL Policies

When using the `client/hexaOpaClient` go package to prepare your authorization request the following attributes are
prepared that can be submitted to the Open Policy Agent service. While any attribute can be referenced in a condition rule, 
the column `IDQL Use` indicates how the attribute is used in IDQL clauses.

| Category | Attribute   | Type                   | Description                                                      | IDQL Use                 |
|----------|-------------|------------------------|------------------------------------------------------------------|--------------------------|
| req      | ip          | string                 | The client TCP/IP address and port (e.g. 127.0.0.1:65151)        | members (net:)           |
|          | protocol    | string                 | The request protocol (http)                                      |                          |
|          | method      | string                 | The HTTP Method (GET, DELETE, PATCH, POST, PUT)                  | Actions (ietf:http:)     |
|          | path        | string                 | The path of the request (e.g. /Users )                           | Actions (ietf:http:)     |
|          | param       | map[string][]string    | A map of all URL query parameters (e.g. /<path>?a=b&c=d          |                          |
|          | header      | map[string][]string    | A map of all HTTP Headers                                        |                          |
|          | time        | time.Time              | The date and time the request was received                       |                          |
|          | actionUris  | []string               | Client app supplied: actionUri(s) to be invoked                  | Actions (uri value)      |
|          | resourceIds | []string               | Client app supplied: The resource_id(s) of the requesting app    | Object (resource_id)     |
| subject  | type        | string                 | The type of authentication (Anonymous basic, or jwt)             |                          |
|          | sub         | string                 | The JWT 'sub" value or the Basic Auth username                   | Members (user:, domain:) |
|          | roles       | []string               | Roles asserted in a JWT assertion                                | Members (role:)          |
|          | claims      | map[string]interface{} | The set of claims received in a JWT assertion                    |                          |
|          | expires     | time.Time              | The expiry time of the JWT received                              |                          |
|          | iat         | time.Time              | The time the JWT was issued                                      |                          |
|          | nbf         | time.Time              | A time before which the certificate should be ignored            |                          |
|          | iss         | string                 | The issuer of the received JWT                                   |                          |
|          | aud         | []string               | An array of values indicating audiences for the use of the token |                          |

For any value above, the Hexa Filter extension process these condition variables. For example `subject.type` refers to the type of authentication.

## Writing IDQL Policy for the HexaOpa

In OPA Rego, IDQL policy is submitted in a JSON format as data input to OPA servers. The [hexaPolicy rego package](server/hexaFilter/test/bundle/hexaPolicyV2.rego) is then used
to compare input (previous section) with IDQL data to determine if access is `allow`ed. 

The following is a template for a typical IDQL policy. The values in brackets are described below:
```json
{
  "meta": {
    "version": "<idql_version>",
    "date": "<date>",
    "description": "<descriptive text>",
    "policyId": "<policyId>"
  },
  "subject": {
    "members": [
      "<type>:<member>"
    ]
  },
  "actions": [
    {
      "actionUri": "<actionUri>"
    }
  ],
  "condition": {
    "rule": "<idql-filter>",
    "action": "<allow|deny>"
  },
  "object": {
    "resource_id": "<app-resource-id>"
  }
}
```

IDQL field values, format and how to use:

| Field           | Format                                                                       | Use                                                    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|-----------------|------------------------------------------------------------------------------|--------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| idql_version    | n.n (typically 0.6)                                                          | Informational                                          | Typically reflects the current IDQL version from [hexa-org/policy-mapper](https://github.com/hexa-org/policy-mapper).                                                                                                                                                                                                                                                                                                                       |
| policyId        | string                                                                       | Required - OPA returns policy ids in `allowSet`        | Used to identify which IDQL policy was matched in rego                                                                                                                                                                                                                                                                                                                                                                                      |
| type:member     | multi-value string                                                           | Matches input subjects                                 | Types: `any`, `anyAuthenticated`, `user:`username/sub, `domain:`domain suffix, `role:`role name, `net:`cidr                                                                                                                                                                                                                                                                                                                                 | 
|                 |                                                                              |                                                        | `any` means any user or anonymous subject<br/>`anyAuthenticated` means any authenticated subject<br/>`user` matches `input.subject.sub` (e.g. `basicbob@hexa.org`)<br/>`domain` matches the suffix of `input.subject.sub` (e.g. `@hexa.org`)<br/>`role` matches `input.subject.roles` (e.g. `admin`)<br/>`net` matches a [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) with `input.req.ip` (e.g. `198.51.100.14/24`) |
| actionUri       |                                                                              | Returned in `actionRights`                             | One of two forms:                                                                                                                                                                                                                                                                                                                                                                                                                           |
|                 | `urn:`name                                                                   | Logical rights permitted                               | Matches against `input.request.actionUris`(asserted by the calling application)                                                                                                                                                                                                                                                                                                                                                             |
|                 | `ietf:http:`method:path                                                      | HTTP Requests Permitted                                | `method` is one of `GET`, `DELETE`, `PATCH`, `POST`, `PUT`, or `*` for any method<br/>`path` is the request path (* to wildcard)                                                                                                                                                                                                                                                                                                            |
| app-resource-id | string                                                                       | The name of the resource the policy is associated with | Matches against `input.request.resourceIds`                                                                                                                                                                                                                                                                                                                                                                                                 |
| idql-filter     | [SCIM Filter](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2.2) | Run-time attribute conditions                          | Filter matches against OPA input attributes (e.g. input.subject.type eq jwt)                                                                                                                                                                                                                                                                                                                                                                |
| allow deny      | `allow` (default) or `deny`                                                  | Determines the outcome of condition                    | If filter is true the policy matches if action is `allow`. Policy does not match if action is `deny`.                                                                                                                                                                                                                                                                                                                                       |

## Demonstration Integrations

This project includes two demonstration OPA integrations. 

### Hexa Industries Demo

The Hexa Industries Demo is a simple application that demonstrates an application integration with HexaOPA using a Middleware style integration. For example:

```go
    opaSupport := decisionsupport.DecisionSupport{Provider: provider, Unauthorized: basic.unauthorized, Skip: []string{"/health", "/metrics", "/styles", "/images", "/bundle", "/favicon.ico"}, ActionMap: actionMap, ResourceId: "hexaIndustries"}
    // ...
    router := server.Handler.(*mux.Router)
    router.Use(opaSupport.Middleware)
```
