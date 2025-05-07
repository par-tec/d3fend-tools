from d3fendtools.kuberdf.base import (
    K8Resource,
    K8S,
    _register,
    D3F,
    RDF,
    strip_oci_image_tag,
)
from rdflib import URIRef, RDFS


@_register
class Role(K8Resource):
    apiVersion = "rbac.authorization.k8s.io/v1"
    kind = "Role"


@_register
class RoleBinding(K8Resource):
    apiVersion = "rbac.authorization.k8s.io/v1"
    kind = "RoleBinding"

    def triple_spec(self):
        for subject in self.manifest.get("subjects", []):
            kind = subject["kind"]
            name = subject["name"]
            if namespace := subject.get("namespace"):
                ns = URIRef(f"https://k8s.local/{namespace}")
            else:
                ns = self.ns

            if kind == "ServiceAccount":
                sa_u = ns + f"/ServiceAccount/{name}"
                yield sa_u, RDF.type, K8S.ServiceAccount
                yield ns, RDF.type, K8S.Namespace
                yield ns, K8S.hasChild, sa_u
                yield sa_u, K8S.hasNamespace, ns
                yield self.uri, D3F.authorizes, sa_u
            elif kind == "User":
                user_u = URIRef(ns + f"/User/{name}")
                yield user_u, RDF.type, K8S.User
                yield ns, K8S.hasChild, user_u
                yield user_u, K8S.hasNamespace, ns
                yield self.uri, D3F.authorizes, user_u

            else:
                raise NotImplementedError(kind)


@_register
class BuildConfig(K8Resource):
    apiVersion = "v1"
    kind = "BuildConfig"

    def triple_spec(self):
        from_image_url = None
        to_image_url = None

        to_ = self.spec.get("output", {}).get("to", {})
        if to_.get("kind") == "ImageStreamTag":
            to_image_url = URIRef(
                self.ns + "/ImageStreamTag/" + strip_oci_image_tag(to_["name"])
            )
            yield self.uri, K8S.writes, to_image_url
            yield to_image_url, RDF.type, K8S.ImageStreamTag

        from_ = self.spec.get("strategy", {}).get("sourceStrategy", {}).get("from", {})
        if from_.get("kind") == "ImageStreamTag":
            ns = from_.get("namespace", self.ns)
            from_image_url = URIRef(
                ns + "/ImageStreamTag/" + strip_oci_image_tag(from_["name"])
            )
            yield self.uri, K8S.reads, from_image_url
            yield from_image_url, RDF.type, K8S.ImageStreamTag
        if from_image_url and to_image_url:
            yield to_image_url, RDFS.subClassOf, from_image_url
