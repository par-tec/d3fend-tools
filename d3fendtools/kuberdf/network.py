from .base import K8Resource, K8S, D3F, SELECTOR_LABELS, _register
from rdflib import RDF, OWL, URIRef, Literal


@_register
class Route(K8Resource):
    apiVersion = "route.openshift.io/v1"
    kind = "Route"

    def triple_spec(self):
        for k, v in self.spec.items():
            if k == "host":
                host_u = URIRef(f"TCP://{v}{self.spec.get('path', '')}:443")
                yield host_u, RDF.type, K8S.Host
                yield host_u, D3F.accesses, self.uri
                yield self.uri, K8S.hasHost, host_u
                yield host_u, K8S.hasNamespace, self.ns
                if self.ns:  # FIXME: Add tests
                    yield self.ns, K8S.hasChild, host_u
                yield self.ns, K8S.hasChild, host_u

            if k == "to":
                rel_kind = v["kind"]
                rel_name = v["name"]

                rel_port = self.spec.get("port", {}).get("targetPort")
                rel_port = f":{rel_port}" if rel_port else ""
                yield (
                    self.uri,
                    D3F.accesses,
                    self.ns + f"/{rel_kind}/{rel_name}{rel_port}",
                )
                # yield self.ns + f"/{rel_kind}/{rel_name}", RDF.type, NS_K8S[rel_kind]
                # rel_port = self.spec.get("port", {}).get("targetPort")
                # dport = URIRef(f"TCP://{rel_name}:{rel_port}")
                # yield self.uri, NS_K8S.hasTarget, dport
                # yield dport, RDF.type, NS_K8S.Port


@_register
class Service(K8Resource):
    apiVersion = "v1"
    kind = "Service"

    def triple_spec(self):
        # Get externalname host or ip
        if external_name := self.spec.get("externalName"):
            # ExternalName can cause troubles.
            # see https://kubernetes.io/docs/concepts/services-networking/service/#externalname
            host_u = URIRef(f"fixme://{external_name}")

            yield host_u, RDF.type, K8S.Host
            yield host_u, D3F.accesses, self.uri
            yield self.uri, K8S.hasHost, host_u

        for port in self.spec.get("ports", []):
            # Explicit internal TCP connections.
            port.setdefault("protocol", "TCP")

            host_u = URIRef(f"{port['protocol']}://{self.name}:{port['port']}")

            yield host_u, RDF.type, K8S.Host
            yield self.uri, K8S.hasHost, host_u
            if port.get("targetPort"):
                yield (
                    self.uri,
                    K8S.portForward,
                    Literal("{port}-{protocol}>{targetPort}".format(**port)),
                )
            if port_name := port.get("name"):
                # host_portname_u = URIRef(
                #     f"{port['protocol']}://{self.name}:{port_name}"
                # )
                # yield host_portname_u, RDF.type, NS_K8S.Host
                # yield self.uri, NS_K8S.hasHost, host_portname_u
                # yield self.uri, NS_K8S.hasChild, host_portname_u
                # yield host_portname_u, NS_D3F.accesses, host_u
                service_port = self.uri + f":{port_name}"
                yield service_port, RDF.type, K8S.Port
                yield self.uri, K8S.hasPort, service_port
                yield self.uri, K8S.hasChild, service_port
                yield service_port, OWL.sameAs, host_u

            # Service port forwarded to selectors.
            service_port = self.uri + f":{port['port']}"
            yield service_port, RDF.type, K8S.Port
            yield self.uri, K8S.hasPort, service_port
            yield self.uri, K8S.hasChild, service_port
            yield host_u, D3F.accesses, service_port

            internal_host_u = URIRef(
                f"{port['protocol']}://{self.name}.{self.namespace}.svc:{port['port']}"
            )
            yield internal_host_u, D3F.accesses, service_port
            yield self.uri, K8S.hasChild, internal_host_u

            if selector := self.spec.get("selector"):
                # selector_label = json.dumps(selector, sort_keys=True).replace('"', "")
                # selector_uuid = hashlib.sha256(selector_label.encode()).hexdigest()
                # selector_u = URIRef(f"urn:k8s:{self.ns}/Selector/{selector_uuid}")
                # yield selector_u, RDF.type, NS_K8S.Selector
                # yield selector_u, RDFS.label, Literal(selector_label)
                # yield selector_u, NS_K8S.hasNamespace, self.ns

                for k, v in selector.items():
                    if k not in SELECTOR_LABELS:
                        continue
                    # k, v = next(iter(selector.items()))
                    # Kubernetes by default exposes all ports on a service
                    endpoint_u = URIRef(
                        f"{{protocol}}://{self.ns}/{k}={v}:{{targetPort}}".format(
                            **port
                        )
                    )
                    yield endpoint_u, RDF.type, K8S.Selector
                    # yield selector_u, NS_K8S.hasChild, endpoint_u
                    # Service port accesses a selector-based Endpoint.
                    yield service_port, D3F.accesses, endpoint_u
                    # yield selector_u, NS_K8S.hasChild, endpoint_u
            else:
                # yield an Endpoint with the same name as the service
                # and on the default namespace.
                endpoint_u = URIRef(f"urn:k8s:default/Endpoints/{self.name}")
                yield self.uri, D3F.accesses, endpoint_u

            # Connect host to Endpoint
            # yield host_u, NS_D3F.accesses, endpoint_u
            yield self.uri, K8S.hasChild, host_u
