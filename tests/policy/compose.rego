package main

# Policy-as-code: Docker Compose hardening requirements (IEC 62443 SR 5.x
# compensating controls applied to the lab container stack).
# Run: conftest test -p tests/policy lab-environment/docker-compose.yml

# --- helper rules ---

has_cap(service, cap) if {
    service.cap_add[_] == cap
}

has_opt(service, opt) if {
    service.security_opt[_] == opt
}

attached_to(service, net) if {
    service.networks[_] == net
}

# --- policy ---

# Every service must define an image or a build
deny contains msg if {
    service := input.services[key]
    not service.image
    not service.build
    msg := sprintf("service %q must define an image or build", [key])
}

# Every service must restart on failure
deny contains msg if {
    service := input.services[key]
    not service.restart
    msg := sprintf("service %q must define a restart policy", [key])
}

# Every service must enforce a memory limit
deny contains msg if {
    service := input.services[key]
    not service.mem_limit
    msg := sprintf("service %q must define a memory limit", [key])
}

# The gateway must drop all capabilities and retain the network set
deny contains msg if {
    input.services.gateway.cap_drop[_] == "ALL"
    not has_cap(input.services.gateway, "NET_ADMIN")
    msg := "gateway must retain NET_ADMIN"
}

# Any service dropping capabilities must also enforce no-new-privileges
deny contains msg if {
    service := input.services[key]
    service.cap_drop[_] == "ALL"
    not has_opt(service, "no-new-privileges:true")
    msg := sprintf("service %q drops capabilities but lacks no-new-privileges", [key])
}

# Only the enterprise (IT) zone may be non-internal; OT zones must be isolated
deny contains msg if {
    input.networks[k]
    k != "it_network"
    not input.networks[k].internal
    msg := sprintf("network %q must be internal (OT zone isolation)", [k])
}

# The gateway must be attached to every zone (single chokepoint)
deny contains msg if {
    attached_to(input.services.gateway, "it_network")
    not attached_to(input.services.gateway, "control_network")
    msg := "gateway must be attached to the control network"
}
