# AuthZen PDP Interop Scenario

## Introduction

The HexaAuthZen server is an implementation of the OpenId Foundation [AuthZen WG](https://openid.net/wg/authzen/) specification which describes the API
between applications (policy enforcement points) and decision services (policy decision points). 
* [AuthZEN Repository](https://github.com/openid/authzen)
* [AuthZEN Interop](https://authzen-interop.net/docs/intro/)

In order to facilitate a simple monolithic server for interop purposes a number of components have been combined into
a single server that include:
* The AuthZen decision endpoint (`/access/v1/evaluation1`)
* An OPA Server Bundle endpoint (enabling IDQL policy retrievals and updates from the [Hexa CLI](https://github.com/hexa-org/policy-mapper/blob/main/docs/HexaAdmin.md))
* A request mapper that converts AuthZen policy decision requests into Hexa Policy-OPA request
* An embedded [Open Policy Agent](https://www.openpolicyagent.org) decision engine
* Optional support for Bearer tokens to secure the bundle endpoint and optionally the AuthZen decision endpoints
* A User Policy Information Provider that provides information about the demo app users
* The set of IDQL policies that implements the TODO application policies.

## The AuthZen Scenario

### Introduction
The AuthZen scenario implements a TODO application which then calls a backend acting as a policy enforcement point (PEP) that
calls a policy decision point (PDP) that supports the Authzen evaluation endpoint.

### Actions

| Description               | URI             |
|---------------------------|-----------------|
| View a user's information | can_read_user   |
| View all Todos            | can_read_todos  |
| Create a Todo             | can_create_todo |
| Can (Un)complete Todo     | can_update_todo |
| Delete a Todo             | can_delete_todo |

### Roles

- viewer - able to view the shared todo list (can_read_todos) as well as information about each of the owners (can_read_user)
- editor - viewer + ability to create new Todos as well as edit and delete owned by that user
- admin - editor + the ability to delete any Todos (can_delete_todo)
- evil_genius - editor + ability to edit Todos that do not belone to the user

### Subjects

```text
  User	PID
  Rick Sanchez	CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs
  Morty Smith	CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs
  Summer Smith	CiRmZDI2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs
  Beth Smith	CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs
  Jerry Smith	CiRmZDQ2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs
```

### IDQL Policy

In this scenario, `can_read_user`, `can_read_todos` ony require that the user be authenticated (member is `anyAuthenticated`).
`can_create_todo`, requires the subject to have either the role `editor` or `admin` (role is asserted by the User PIP). 
The first 3 policies are evaluated using the normal `hexaPolicy.rego` processor.

The policies `can_update_todo` and `can_delete_todo` are ABAC policies that require either a role or relationship with 
the TODO being edited. An IDQL Condition is used with the `hexaFilter` OPA extension:
```json lines
"condition": {
  "rule": "subject.roles co admin or (subject.roles co editor and resource.ownerID eq subject.claims.id)",
  "action": "allow"
}
```

The following IDQL policies are used:
```json
{
  "policies": [
    {
      "meta": {
        "policyId": "GetUsers",
        "version": "0.6",
        "description": "Get information (e.g. email, picture) associated with a user"
      },
      "subject": {
        "members": ["anyAuthenticated"]
      },
      "actions": [
        {
          "actionUri": "can_read_user"
        }
      ],
      "object": {
        "resource_id": "todo"
      }
    },
    {
      "meta": {
        "policyId": "GetTodos",
        "version": "0.6",

        "description": "Get the list of todos. Always returns true for every user??"
      },
      "subject": {
        "members": ["anyAuthenticated"]
      },
      "actions": [
        {
          "actionUri": "can_read_todos"
        }
      ],
      "object": {
        "resource_id": "todo"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "description": "Create a new Todo",
        "policyId": "PostTodo"
      },
      "subject": {
        "members": ["role:admin","role:editor"]
      },
      "actions": [
        {
          "actionUri": "can_create_todo"
        }
      ],
      "object": {
        "resource_id": "todo"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "description": "Edit(complete) a todo.",
        "policyId": "PutTodo"
      },
      "subject": {
        "members": ["anyAuthenticated"]
      },
      "actions": [
        {
          "actionUri": "can_update_todo"
        }
      ],
      "condition": {
        "rule": "subject.roles co evil_genius or (subject.roles co editor and resource.ownerID eq subject.claims.id)",
        "action": "allow"
      },
      "object": {
        "resource_id": "todo"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "description": "Delete a todo if admin or owner of todo",
        "policyId": "DeleteTodo"
      },
      "subject": {
        "members": ["anyAuthenticated"]
      },
      "actions": [
        {
          "actionUri": "can_delete_todo"
        }
      ],
      "condition": {
        "rule": "subject.roles co admin or (subject.roles co editor and resource.ownerID eq subject.claims.id)",
        "action": "allow"
      },
      "object": {
        "resource_id": "todo"
      }
    }
  ]
}
```

### Environment Variables

| ENV Var               | Description                                                                                                                             |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| PORT                  | The HTTP Port for all endpoints                                                                                                         |
| AUTHZEN_BUNDLE_DIR    | The location of an OPA Bundle containing hexaPolicy.rego, and data.json containing the ToDo Application IDQL                            |
| AUTHZEN_USERPIP_FILE  | The location of a JSON file containing the test users                                                                                   |
| AUTHZEN_TKN_DIRECTORY | THe location of a directory that contains the JWT token issuer public key (file issuer-cert.pem)                                        |
| AUTHZEN_TKN_MODE      | If set to "ANON", all access is unauthenticated, "BUNDLE", the bundle endpoint is protected. "ALL" (default) will enforce all endpoints |
| TKN_ISSUER            | The key id (kid) of the issuer - used to match the kid in a JWT with the public key                                                     |


