# Hexa Integration Support for Open Policy Agent (OPA)

This OPA Integration project extends support for Hexa IDQL Policy running inside an Open Policy Agent (OPA) server. 
Support includes new functionality for condition expressions new to IDQL
support. This integration includes:
* ConditionInfo type definition (`/policySupport/conditions/conditions.go`)
* Rego enhancements to add condition expression testing (see below)
* hexaFilter plugin which evaluates an IDQL condition filter against provided input (see below)
* hexaOpa server which bundles hexaFilter as an OPA executable

> [!Note]
> This project is intended to work with the [Hexa Policy Mapper Project](https://github.com/hexa-org/policy-mapper).

## Extending OPA Server
To build the new version of OPA with the hexaPlugin included perform the following:
```bash
cd cmd/hexaOpa
go build -o hexaOpa

# to start, run like a normal hexaOpa server except with the new image:
./hexaOne run --server --config-file config.yaml
```

## OPA Client Integration and Example IDQL
The `hexaFilter` evaluates input structures provided by `client/opa/opaTools` request builder using
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
          "name": "createProfileIP",
          "actionUri": "ietf:http:POST:/testpath*"
        },
        { "name": "editProfileIP",
          "actionUri": "ietf:http:PUT:/testpath*",
          "exclude": true
        },
        { "name": "getProfileIP",
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

## Hexa Rego Enhancment
The Hexa IDQL Rego may be enhanced to invoike the Conditions plugin with the following code:
```rego
# Returns the list of matching policy names based on current request
<...>
allowSet[name] {
    some i
    subjectMatch(policies[i].subject)
    subjectMembersMatch(policies[i].subject)
    subjectRoleMatch(policies[i].subject)
    actionsMatch(policies[i].actions)
    objectMatch(policies[i].object)
    conditionMatch(policies[i])
    policies[i].id
    name := policies[i].id  # this will be id of the policy
}
<...>
conditionMatch(policy) {
    not policy.condition  # Most policies won't have a condition
}

conditionMatch(policy) {
    policy.condition
    policy.condition.rule
    hexaFilter(policy.condition.rule,input)  # HexaFilter evaluations the rule for a match against input
}
<...>
```
In the above **rego**, the first conditionMatch block allows a rule to proceed if no condition is specified. If a condition value is 
specified, the second block invokes `hexaFilter(policy.condition.rule,input)`  which provides
the available request input in json form. The plugin checks the condition expression against the input for a match.

Note that the current implementation ignores the "action" phrase of the condition which could be allow / deny / audit.  
allow is the default, deny inverts the policy rule (to deny an action). Audit is used in some systems to simply "log" the rule pass/failure
for testing purposes.  IDDQL implementations currently do not use this but it is included for compatibility with platforms like Azure.


