package example.rule


allow["All containers allowed"] {
    count(deny) == 0
}

deny[{"Container": container.name, "Details": {"msg": msg}}] {

	some container
    input_containers[container]
	not container.securityContext.privileged == "false"
    msg := sprintf("Container '%v' has privileged set to true: illegal configuration", [container.name])
	
}

input_containers[container] {
	re_match("^(Pod|Deployment)$", input.request.kind.kind)
	container := input.request.object.spec.containers[_]
}
