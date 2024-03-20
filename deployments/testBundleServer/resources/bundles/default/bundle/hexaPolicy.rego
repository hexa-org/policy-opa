package hexaPolicy

# Rego Policy Interpreter for V1.0 hexaPolicy (IDQL)
import rego.v1

import data.policies

# Returns whether the current operation is allowed
allow if {
	count(allowSet) > 0
}

# Returns the list of possible actions allowed (e.g. for UI buttons)
actionRights contains name if {
	some policy in policies
	policy.id in allowSet

	some action in policy.actions
	name := sprintf("%s/%s", [policy.id, action.actionUri])
}

# Returns the list of matching policy names based on current request
allowSet contains name if {
	some policy in policies
	subjectMatch(policy.subject, input.subject, input.req)
	subjectMembersMatch(policy.subject)
	subjectRoleMatch(policy.subject, input.subject)
	actionsMatch(policy.actions, input.req)
	objectMatch(policy.object, input.req)
	conditionMatch(policy, input)

	name := policy.id # this will be id of the policy
}

subjectMembersMatch(subject) if {
	# Match if no members value specified
	not subject.members
}

subjectMembersMatch(subject) if {
	subject.members

	some member in subject.members
	lower(input.subject.sub) == lower(member)
}

subjectRoleMatch(subject, _) if {
	not subject.role
}

subjectRoleMatch(subject, insubj) if {
	subject.role
	insubj.roles
	some role in insubj.roles
	lower(subject.role) == lower(role)
}

subjectMatch(subject, _, _) if {
	# If policy is any that we will skip processing of subject
	lower(subject.type) == "any"
}

subjectMatch(subject, insubj, _) if {
	# anyAutheticated - A match occurs if input.subject has a value other than anonymous and exists.
	insubj.sub # check sub exists
	lower(subject.type) == "anyauthenticated"
	not lower(insubj.type) == "anonymous"
}

subjectMatch(subject, _, req) if {
	# A subject is authenticated by having the correct IP that is contained by the CIDR value
	lower(subject.type) == "net"
	parts := split(req.ip, ":")
	net.cidr_contains(subject.cidr, parts[0])
}

subjectMatch(subject, insubj, _) if {
	# Basic Auth assumes that another middleware function has in validated the basic authorization.
	# Just check for basic auth type
	lower(subject.type) == "basic"
	lower(insubj.type) == "basic"
	insubj.sub # A username was matched
}

subjectMatch(subject, insubj, _) if {
	subject.type == "jwt"

	# note: in the future there may be other JWT token types (e.g. DPOP)
	lower(insubj.type) == "bearer+jwt"
	checkJwtIssuer(subject, insubj)
	checkAudience(subject, insubj)
}

checkJwtIssuer(subject, _) if {
	# no policy issuer is acceptable
	not subject.config.iss
}

checkJwtIssuer(subject, insubj) if {
	# Is glob case-insensitive?
	glob.match(subject.config.iss, ["*"], insubj.iss)
}

checkAudience(subject, _) if {
	# no policy audience is acceptable
	not subject.config.aud
}

checkAudience(subject, insubj) if {
	# Is glob case-insensitive?
	some aud in insubj.aud
	glob.match(subject.config.aud, ["*"], aud)
}

actionsMatch(actions, _) if {
	# no actions is a match
	not actions
}

actionsMatch(actions, req) if {
	some action in actions
	actionMatch(action, req)
}

actionMatch(action, req) if {
	# handles actions where exclude is false or not set
	action.actionUri # check for an action

	# For now, in OPA we will assume only IETF HTTP protocols are used
	# Do we need an extension mechanism?
	checkIetfMatch(action.actionUri, req)
}

checkIetfMatch(actionUri, req) if {
	# first match the rule against literals
	components := split(lower(actionUri), ":")
	count(components) > 2
	components[0] == "ietf"
	startswith(components[1], "http")

	startswith(lower(input.req.protocol), "http")
	checkHttpMethod(components[2], req.method)

	checkPath(components[3], req)
}

# Note:  see https://www.openpolicyagent.org/docs/latest/policy-performance/
objectMatch(object, req) if {
	checkPath(object.pathSpec, req)
}

objectMatch(object, req) if {
	regex.match(object.pathRegEx, req.path)
	# what about query parameters?
}

checkHttpMethod(allowMask, _) if {
	contains(allowMask, "*")
}

checkHttpMethod(allowMask, reqMethod) if {
    startswith(allowMask,"!")

	not contains(allowMask, lower(reqMethod))
}

checkHttpMethod(allowMask, reqMethod) if {
    not startswith(allowMask,"!")
	contains(allowMask, lower(reqMethod))
}

checkPath(path, req) if {
	path # if path specified it must match
	glob.match(path, ["*"], req.path)
}

checkPath(path, _) if {
	not path # if path not specified, it will not be matched
}

conditionMatch(policy, _) if {
	not policy.condition # Most policies won't have a condition
}

conditionMatch(policy, inreq) if {
	policy.condition
	hexaFilter(policy.condition.rule, inreq) # HexaFilter evaluations the rule for a match against input
}
