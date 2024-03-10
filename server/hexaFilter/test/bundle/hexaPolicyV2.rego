package hexaPolicy

# Rego Policy Interpreter for V1.0 hexaPolicy (IDQL)
import future.keywords.in
import data.policies

default allow = false

# Returns whether the current operation is allowed
allow {
    count(allowSet) > 0
}

# Returns the list of possible actions allowed (e.g. for UI buttons)
actionRights[name] {
	some i
    policies[i].id == allowSet[_]
	name := calcActionName(policies[i].actions[_],policies[i].id)
}

calcActionName(action,id) = val {
	action.exclude == true

    val := sprintf("!%s/%s",[id,action.name])
}
calcActionName(action,id) = val {
	not (action.exclude == true)
    val := sprintf("%s/%s",[id,action.name])
}

# Returns the list of matching policy names based on current request
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

subjectMembersMatch(subject) {
    # Match if no members value specified
    not subject.members
}

subjectMembersMatch(subject) {
    subject.members
    lower(input.subject.sub) == lower(subject.members[_])
}

subjectRoleMatch(subject) {
    not subject.role
}

subjectRoleMatch(subject) {
    subject.role
    input.subject.roles
    lower(subject.role) == lower(input.subject.roles[_])
}

subjectMatch(subject) {
    # If policy is any that we will skip processing of subject
    lower(subject.type) == "any"
}

subjectMatch(subject) {
    # anyAutheticated - A match occurs if input.subject has a value other than anonymous and exists.
    input.subject.sub # check sub exists
    lower(subject.type) == "anyauthenticated"
    not lower(input.subject.type) == "anonymous"
}

subjectMatch(subject) {
    # A subject is authenticated by having the correct IP that is contained by the CIDR value
    lower(subject.type) == "net"
    parts := split(input.req.ip,":")
    net.cidr_contains(subject.cidr,parts[0])
}

subjectMatch(subject) {
    # Basic Auth assumes that another middleware function has in validated the basic authorization.
    # Just check for basic auth type
    lower(subject.type) == "basic"
    lower(input.subject.type) == "basic"
    input.subject.sub #A username was matched
}

subjectMatch(subject) {
    subject.type == "jwt"
    # note: in the future there may be other JWT token types (e.g. DPOP)
    lower(input.subject.type) == "bearer+jwt"
    checkJwtIssuer(subject)
    checkAudience(subject)
}

checkJwtIssuer(subject) {
    #no policy issuer is acceptable
    not subject.config.iss
}
checkJwtIssuer(subject) {
    subject.config.iss
    # Is glob case-insensitive?
    glob.match(subject.config.iss, ["*"], input.subject.iss)
}

checkAudience(subject) {
    #no policy audience is acceptable
    not subject.config.aud
}
checkAudience(subject) {
    subject.config.aud
    # Is glob case-insensitive?
    glob.match(subject.config.aud, ["*"], input.subject.aud)
}

actionsMatch(actions) {
    # no actions is a match
    not actions
}
actionsMatch(actions) {
    some i
    actionMatch(actions[i])
}

actionMatch(action) {
    # handles actions where exclude is false or not set
    action.actionUri # check for an action
    not (action.exclude == true)

    # For now, in OPA we will assume only IETF HTTP protocols are used
    # Do we need an extension mechanism?
    checkIetfMatch(action.actionUri)
}
actionMatch(action) {
    # handles actions with exclude set
    action.exclude == true
    action.actionUri
    # Verify not having a match is correct
    not checkIetfMatch(action.actionUri)
}

checkIetfMatch(actionUri) {
    # first match the rule against literals
    components := split(lower(actionUri),":")
    count(components) > 2
    components[0] == "ietf"
    startswith(components[1],"http")

    startswith(lower(input.req.protocol),"http")
    checkHttpMethod(components[2],input.req.method)

    checkPath(components[3])
   
}

# Note:  see https://www.openpolicyagent.org/docs/latest/policy-performance/
objectMatch(object) {
    object.pathSpec  # check if pathSpec exists
    checkPath(object.pathSpec)
}

objectMatch(object) {
    object.pathRegEx  # check if pathRegEx exists
    regex.match(object.pathRegEx,input.req.path)
    # what about query parameters?
}

checkHttpMethod(allowMask,reqMethod) {
    contains(allowMask, "*")
}

checkHttpMethod(allowMask,reqMethod) {
    contains(allowMask,lower(reqMethod))
}

checkPath(path) {
    path # if path specified it must match
    glob.match(path,["*"],input.req.path)
}

checkPath(path) {
    not path # if path not specified, it will not be matched
}

conditionMatch(policy) {
    not policy.condition  # Most policies won't have a condition
}

conditionMatch(policy) {
    policy.condition
    policy.condition.rule
    hexaFilter(policy.condition.rule,input)  # HexaFilter evaluations the rule for a match against input
}