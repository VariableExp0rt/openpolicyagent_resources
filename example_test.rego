package example.test_rule


import data.example.rule

test_unsafe_security_context {
  unsafe_config := {                                       
    "request": {
      "kind": {"kind": "Pod"},
      "object": {
        "spec": {
          "containers": [
            {"name": "my-opa-unit-test"},
            {"image": "busybox"},
            {"securityContext": {"privileged": "true"}}
          ]
        }
      }
    }
  }
	count(rule.deny) == 1 with input as unsafe_config 
}

test_safe_security_context {
  safe_config := {                                       
    "request": {
      "kind": {"kind": "Pod"},
      "object": {
        "spec": {
          "containers": [
            {"image": "hooli.com/nginx"},
            {"image": "busybox"},
	    {"securityContext": {"privileged": "false"}}
          ]
        }
      }
    }
  }

	count(rule.allow) == 1 with input as safe_config
}
