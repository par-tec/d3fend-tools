from .base import _register, K8Resource, K8S, D3F
from rdflib import RDF


@_register
class ExternalSecret(K8Resource):
    apiVersion = "external-secrets.io/v1beta1"
    kind = "ExternalSecret"

    def triple_spec(self):
        if target := self.spec.get("target", {}).get("name"):
            target_uri = self.ns + f"/Secret/{target}"
            yield target_uri, RDF.type, K8S.Secret
            yield target_uri, K8S.hasNamespace, self.ns
            yield self.ns, K8S.hasChild, target_uri
            yield self.uri, D3F.creates, target_uri

        if secret_store_ref := self.spec.get("secretStoreRef"):
            secret_store_uri = self.ns + f"/SecretStore/{secret_store_ref['name']}"
            yield secret_store_uri, RDF.type, K8S.SecretStore
            yield secret_store_uri, D3F.authorizes, self.uri
            yield secret_store_uri, K8S.hasNamespace, self.ns
            yield self.ns, K8S.hasChild, secret_store_uri


@_register
class PushSecret(K8Resource):
    apiVersion = "external-secrets.io/v1alpha1"
    kind = "PushSecret"

    def triple_spec(self):
        if secret := self.spec.get("target", {}).get("name"):
            target_uri = self.ns + f"/Secret/{secret}"
            yield target_uri, RDF.type, K8S.Secret
            yield target_uri, K8S.hasNamespace, self.ns
            yield self.ns, K8S.hasChild, target_uri
            yield self.uri, D3F.creates, target_uri

        if secret := self.spec.get("selector", {}).get("secret", {}).get("name"):
            target_uri = self.ns + f"/Secret/{secret}"
            yield target_uri, RDF.type, K8S.Secret
            yield target_uri, K8S.hasNamespace, self.ns
            yield self.ns, K8S.hasChild, target_uri
            yield self.uri, D3F.reads, target_uri

        if secret_store_ref := self.spec.get("secretStoreRef"):
            secret_store_uri = self.ns + f"/SecretStore/{secret_store_ref['name']}"
            yield secret_store_uri, RDF.type, K8S.SecretStore
            yield secret_store_uri, D3F.authorizes, self.uri
            yield secret_store_uri, K8S.hasNamespace, self.ns
            yield self.ns, K8S.hasChild, secret_store_uri
