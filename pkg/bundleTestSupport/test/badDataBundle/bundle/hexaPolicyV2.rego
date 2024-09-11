package hexaPolicy

# Rego Hexa Policy Interpreter v0.7.0
import rego.v1

import data.bundle.policies

hexa_rego_version := "0.7.0"

policies_evaluated := count(policies)

# Returns the list of matching policy names based on current request
allow_set contains policy_id if {
	some policy in policies

	# return id of the policy
	policy_id := sprintf("%s", [policy.meta.policyId])

	subject_match(policy.subject, input.subject, input.req)

	actions_match(policy.actions, input.req)

	object_match(policy.object, input.req)

	condition_match(policy, input)
}

scopes contains scope if {
    some policy in policies
    policy.meta.policyId in allow_set

    scope := {
        "policyId": policy.meta.policyId,
        "scope": policy.scope
    }
}

# Returns the list of possible actions allowed (e.g. for UI buttons)
action_rights contains name if {
	some policy in policies
	policy.meta.policyId in allow_set

	some action in policy.actions
	name := sprintf("%s:%s", [policy.meta.policyId, action])
}

# Returns whether the current operation is allowed
allow if {
	count(allow_set) > 0
}

subject_match(psubject, _, _) if {
	# Match if no value specified - treat as wildcard
	not psubject
}

subject_match(psubject, insubject, req) if {
	# Match if a member matches
	some member in psubject
	subject_member_match(member, insubject, req)
}

subject_member_match(member, _, _) if {
	# If policy is any that we will skip processing of subject
	lower(member) == "any"
}

subject_member_match(member, insubj, _) if {
	# anyAutheticated - A match occurs if input.subject has a value other than anonymous and exists.
	insubj.sub # check sub exists
	lower(member) == "anyauthenticated"
}

# Check for match based on user:<sub>
subject_member_match(member, insubj, _) if {
	startswith(lower(member), "user:")
	user := substring(member, 5, -1)
	lower(user) == lower(insubj.sub)
}

# Check for match if sub ends with domain
subject_member_match(member, insubj, _) if {
	startswith(lower(member), "domain:")
	domain := lower(substring(member, 7, -1))
	endswith(lower(insubj.sub), domain)
}

# Check for match based on role
subject_member_match(member, insubj, _) if {
	startswith(lower(member), "role:")
	role := substring(member, 5, -1)
	role in insubj.roles
}

subject_member_match(member, _, req) if {
	startswith(lower(member), "net:")
	cidr := substring(member, 4, -1)
	addr := split(req.ip, ":") # Split because IP is address:port
	net.cidr_contains(cidr, addr[0])
}

actions_match(actions, _) if {
	# no actions is a match
	not actions
}

actions_match(actions, req) if {
	some action in actions
	action_match(action, req)
}

action_match(action, req) if {
	# Check for match based on ietf http
	check_http_match(action, req)
}

action_match(action, req) if {
	action # check for an action
	count(req.actionUris) > 0

	# Check for a match based on req.ActionUris and actionUri
	check_urn_match(action, req.actionUris)
}

check_urn_match(policyUri, actionUris) if {
	some action in actionUris
	lower(policyUri) == lower(action)
}

check_http_match(actionUri, req) if {
	# first match the rule against literals
	comps := split(lower(actionUri), ":")
	count(comps) > 1

	startswith(lower(comps[0]), "http")
	startswith(lower(req.protocol), "http")

	check_http_method(comps[1], req.method)

	pathcomps := array.slice(comps, 2, count(comps))
	path := concat(":", pathcomps)
	check_path(path, req)
}

object_match(object, _) if {
	not object
}

object_match(object, req) if {
	object

	some request_uri in req.resourceIds
	lower(object) == lower(request_uri)
}

check_http_method(allowMask, _) if {
	contains(allowMask, "*")
}

check_http_method(allowMask, reqMethod) if {
	startswith(allowMask, "!")

	not contains(allowMask, lower(reqMethod))
}

check_http_method(allowMask, reqMethod) if {
	not startswith(allowMask, "!")
	contains(allowMask, lower(reqMethod))
}

check_path(path, req) if {
	path # if path specified it must match
    glob.match(path, ["*"], req.path)
}

check_path(path, _) if {
	not path # if path not specified, it will not be matched
}

condition_match(policy, _) if {
	not policy.condition # Most policies won't have a condition
}

condition_match(policy, inreq) if {
	policy.condition
	not policy.condition.action # Default is to allow
	hexaFilter(policy.condition.rule, inreq) # HexaFilter evaluations the rule for a match against input
}

condition_match(policy, inreq) if {
	policy.condition
	action_allow(policy.condition.action) # if defined, action must be "allow"
	hexaFilter(policy.condition.rule, inreq) # HexaFilter evaluations the rule for a match against input
}

condition_match(policy, inreq) if {
	# If action is deny, then hexaFilter must be false
	policy.condition
	not action_allow(policy.condition.action)
	not hexaFilter(policy.condition.rule, inreq) # HexaFilter evaluations the rule for a match against input
}

# Evaluate whether the condition is set to allow
action_allow(val) if lower(val) == "allow"
