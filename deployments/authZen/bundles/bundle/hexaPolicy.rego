package hexaPolicy

# Rego Hexa Policy Interpreter v0.7.2
import rego.v1

import data.bundle.policies

hexa_rego_version := "0.8.5"

policies_evaluated := count(policies)

error_idql contains item if {
	some policy in policies
	item := diag_error_idundef(policy)
}

error_idql contains item if {
	some policy in policies
	count(policy.subjects) < 1
	item := {
		"policyId": policy.meta.policyId,
		"error": "missing value for subjects",
	}
}

error_idql contains item if {
	some policy in policies
	item := diag_error_version(policy)
}

diag_error_idundef(policy) := diag if {
	not policy.meta.policyId
	diag := {
		"policyId": "undefined",
		"error": "idql policy missing value for meta.policyId",
	}
}

diag_error_version(policy) := diag if {
	policy.meta.version < "0.7"
	diag := {
		"policyId": policy.meta.policyId,
		"error": "Hexa Rego 0.7 requires IDQL version 0.7 or later",
	}
}

deny_set contains policy_id if {
	some policy in policies

	# return id of the policy
	policy_id := sprintf("%s", [policy.meta.policyId])

	subject_match(policy, input.subject, input.req)

	actions_match(policy, input.req)

	is_object_match(policy, input.req)

	condition_rule_match(policy, input)

	action_disallow(policy)
}

# Returns the list of matching policy names based on current request
allow_set contains policy_id if {
	some policy in policies

	# return id of the policy
	policy_id := sprintf("%s", [policy.meta.policyId])

	subject_match(policy, input.subject, input.req)

	actions_match(policy, input.req)

	is_object_match(policy, input.req)

	condition_rule_match(policy, input)

	action_allow(policy)
}

scopes contains scope if {
	some policy in policies
	policy.meta.policyId in allow_set

	scope := {
		"policyId": policy.meta.policyId,
		"scope": policy.scope,
	}
}

# Returns the list of possible actions allowed (e.g. for UI buttons)
action_rights contains name if {
	some policy in policies
	policy.meta.policyId in allow_set

	some action in policy.actions
	name := sprintf("%s:%s", [policy.meta.policyId, action])
}

# Returns the list of possible actions where actions is empty
action_rights contains name if {
	some policy in policies
	policy.meta.policyId in allow_set

	count(policy.actions) == 0
	name := sprintf("%s:*", [policy.meta.policyId])
}

# Returns whether the current operation is allowed
allow if {
	count(deny_set) == 0 # if any denys are matched the request is denied
	count(allow_set) > 0
}

subject_match(policy, _, _) if {
	# Equivalent to "any"
	not policy.subjects
}

subject_match(policy, _, _) if {
	# Equivalent to "any"
	count(policy.subjects) == 0
}

subject_match(policy, inputsubject, req) if {
	# Match if a member matches
	some member in policy.subjects
	subject_member_match(member, inputsubject, req)
}

subject_member_match(member, _, _) if {
	# If policy is any that we will skip processing of subject
	lower(member) == "any"
}

subject_member_match(member, inputsubject, _) if {
	# anyAutheticated - A match occurs if input.subject has a value other than anonymous and exists.
	inputsubject.sub # check sub exists
	lower(member) == "anyauthenticated"
}

# Check for match if sub ends with domain
subject_member_match(member, inputsubject, _) if {
	startswith(lower(member), "domain:")
	domain := lower(substring(member, 7, -1))
	endswith(lower(inputsubject.sub), domain)
}

# Check for match based on policy user:<sub> and sub with no type (this is the defaults to User entity type case)
subject_member_match(member, inputsubject, _) if {
	startswith(lower(member), "user:")
	user := substring(member, 5, -1)
	not contains(inputsubject.sub, ":")
	lower(user) == lower(inputsubject.sub)
}

# Check for match based on <entityType>:<name> - Entity Equality
subject_member_match(member, inputsubject, _) if {
	contains(member, ":")
	not endswith(member, ":")
	contains(inputsubject.sub, ":")
	lower(member) == lower(inputsubject.sub)
}

# Check for Entity Type Is  (subjects = ["User:", "Customer:"] )
subject_member_match(member, inputsubject, _) if {
	endswith(member, ":")
	colon_index := indexof(inputsubject.sub, ":")
	not colon_index < 1

	# get the entity_type including the colon
	entity_type = substring(inputsubject.sub, 0, colon_index + 1)

	# compare the member with colon and entity type with colon
	lower(member) == lower(entity_type)
}

# Check for match based on role
subject_member_match(member, inputsubject, _) if {
	startswith(lower(member), "role:")
	role := substring(member, 5, -1)
	role in inputsubject.roles
}

subject_member_match(member, _, req) if {
	startswith(lower(member), "net:")
	cidr := substring(member, 4, -1)
	addr := split(req.ip, ":") # Split because IP is address:port
	net.cidr_contains(cidr, addr[0])
}

actions_match(policy, _) if {
	# no actions is a match
	not policy.actions
}

actions_match(policy, _) if {
	# no actions is a match
	count(policy.actions) == 0
}

actions_match(policy, req) if {
	some action in policy.actions
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

is_object_match(policy, _) if {
	not policy.object
}

is_object_match(policy, _) if {
	policy.object == ""
}

is_object_match(policy, req) if {
	policy.object != ""

	some request_uri in req.resourceIds
	lower(policy.object) == lower(request_uri)
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

condition_rule_match(policy, _) if {
	not policy.condition # Most policies won't have a condition
}

condition_rule_match(policy, inreq) if {
	policy.condition
	policy.condition.rule
	hexaFilter(policy.condition.rule, inreq) # HexaFilter evaluations the rule for a match against input
}

condition_rule_match(policy, _) if {
	policy.condition
	not policy.condition.rule
}

# Evaluate whether the condition is set to allow
action_allow(policy) if {
	policy.condition.action
	lower(policy.condition.action) == "allow"
}

action_allow(policy) if {
	not policy.condition.action
}

action_disallow(policy) if {
	policy.condition.action
	not lower(policy.condition.action) == "allow"
}
