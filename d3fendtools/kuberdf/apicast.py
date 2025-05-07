from .base import K8Resource, RDF, K8S, D3F, _register


@_register
class DeveloperAccount(K8Resource):
    apiVersion = "capabilities.3scale.net/v1beta1"
    kind = "DeveloperAccount"

    def triple_spec(self):
        providerAccountRef = self.spec.get("providerAccountRef", {}).get("name")
        if providerAccountRef:
            secret_uri = self.ns + f"/Secret/{providerAccountRef}"
            yield secret_uri, RDF.type, K8S.Secret
            yield self.ns, K8S.hasChild, secret_uri
            yield secret_uri, K8S.hasNamespace, self.ns
            yield self.uri, D3F.reads, secret_uri


@_register
class DeveloperUser(K8Resource):
    apiVersion = "capabilities.3scale.net/v1beta1"
    kind = "DeveloperUser"

    def triple_spec(self):
        if developerAccount := self.spec.get("developerAccount", {}).get("name"):
            developer_uri = self.ns + f"/DeveloperAccount/{developerAccount}"
            yield developer_uri, RDF.type, K8S.DeveloperAccount
            yield self.ns, K8S.hasChild, developer_uri
            yield developer_uri, K8S.hasNamespace, self.ns
            yield self.uri, D3F.reads, developer_uri
        if providerAccountRef := self.spec.get("providerAccountRef", {}).get("name"):
            secret_uri = self.ns + f"/Secret/{providerAccountRef}"
            yield secret_uri, RDF.type, K8S.Secret
            yield self.ns, K8S.hasChild, secret_uri
            yield secret_uri, K8S.hasNamespace, self.ns
            yield self.uri, D3F.reads, secret_uri
        if passwordCredentials := self.spec.get("passwordCredentialsRef", {}).get(
            "name"
        ):
            secret_uri = self.ns + f"/Secret/{passwordCredentials}"
            yield secret_uri, RDF.type, K8S.Secret
            yield self.ns, K8S.hasChild, secret_uri
            yield secret_uri, K8S.hasNamespace, self.ns
            yield self.uri, D3F.reads, secret_uri
