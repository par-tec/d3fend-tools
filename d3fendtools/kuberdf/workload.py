from d3fendtools.kuberdf.base import (
    _register,
    D3F,
    K8S,
    K8Resource,
    RDF,
    strip_oci_image_tag,
    parse_url,
    SELECTOR_LABELS,
)
from rdflib import URIRef, RDFS, Literal
from urllib.parse import urlparse


@_register
class Deployment(K8Resource):
    """
    DeploymentConfig
    $.spec.template.spec.containers[*]
    """

    apiVersion = "apps/v1"
    kind = "Deployment"

    @staticmethod
    def parse_image(image, container_uri=None):
        image_url_type = len(image.split("/"))
        if image_url_type == 1:  # only image name
            image = "https://docker.io/library/" + image
        elif image_url_type == 2:  # image name and organization
            image = "https://docker.io/" + image
        elif image_url_type == 3:  # image name, organization and registry
            image = "https://" + image
        else:
            pass

        image_url = urlparse(image)
        image_uri = URIRef(
            image_url._replace(path=strip_oci_image_tag(image_url.path)).geturl()
        )
        if image_url.netloc:
            registry_uri = URIRef(image_url.scheme + "://" + image_url.netloc)
            yield registry_uri, RDF.type, K8S.Registry
            yield registry_uri, K8S.hasChild, image_uri

        yield image_uri, RDF.type, K8S.Image
        if container_uri:
            yield container_uri, K8S.hasImage, image_uri
            yield container_uri, D3F.runs, image_uri

    def triple_spec(self):
        if not (template := self.spec.get("template")):
            return
        containers = template.get("spec", {}).get("containers", [])
        volumes = template.get("spec", {}).get("volumes", [])
        metadata = template.get("metadata", {})
        template_labels = metadata.get("labels", {})
        template_app = self.get_app_uri(metadata) or self.app

        if serviceAccount := template.get("spec", {}).get("serviceAccountName"):
            service_account = self.ns + f"/ServiceAccount/{serviceAccount}"
            yield service_account, RDF.type, K8S.ServiceAccount
            yield self.ns, K8S.hasChild, service_account
            yield service_account, D3F.executes, self.uri

        for volume in volumes:
            if "persistentVolumeClaim" in volume:
                pvc = volume["persistentVolumeClaim"]["claimName"]
                s_volume = self.ns + f"/PersistentVolumeClaim/{pvc}"
                yield self.uri, K8S.hasVolume, s_volume
                yield self.uri, D3F.accesses, s_volume
                yield s_volume, RDF.type, K8S.PersistentVolumeClaim
                # XXX: the volume can be mounted in multiple applications.
                if template_app:
                    yield template_app, K8S.hasChild, s_volume
                else:
                    yield self.ns, K8S.hasChild, s_volume
            elif "secret" in volume:
                secret = volume["secret"]["secretName"]
                s_volume = self.ns + f"/Secret/{secret}"
                yield self.uri, K8S.hasVolume, s_volume
                yield self.uri, D3F.reads, s_volume
                yield s_volume, RDF.type, K8S.Secret
                yield self.ns, K8S.hasChild, s_volume
            elif "configMap" in volume:
                configmap = volume["configMap"]["name"]
                s_volume = self.ns + f"/ConfigMap/{configmap}"
                yield self.uri, K8S.hasVolume, s_volume
                yield self.uri, D3F.reads, s_volume
                yield s_volume, RDF.type, K8S.ConfigMap
                yield self.ns, K8S.hasChild, s_volume
            elif "hostPath" in volume:
                if self.namespace.startswith(
                    (
                        "kube-system",
                        # "openshift-",
                        "rook-",
                    )
                ):
                    # Ignore hostPath volumes in kube-system
                    continue
                raise NotImplementedError
            elif "emptyDir" in volume:
                # Ignore emptyDir volumes
                continue
            else:
                # """
                # TODO: {'name': 'console-serving-cert',
                #  'secret': {'defaultMode': 420, 'secretName': 'console-serving-cert'}}
                #
                # """
                raise NotImplementedError(volume)

        for container in containers:
            s_container = self.uri + f"/Container/{container['name']}"
            yield self.uri, D3F.runs, s_container
            yield s_container, RDF.type, K8S.Container
            yield s_container, RDFS.label, Literal(container["name"])
            yield self.uri, K8S.hasChild, s_container
            if self.app:
                yield self.app, K8S.hasChild, s_container

            if "image" in container:
                image = Deployment.parse_image(
                    container["image"], container_uri=s_container
                )
                yield from image

            ports = [p.get("containerPort") for p in container.get("ports", [])]
            ports += [
                container.get(p, {}).get("httpGet", {}).get("port")
                for p in ("livenessProbe", "readinessProbe", "startupProbe")
            ]
            for port in ports:
                if not port:
                    continue
                protocol = "TCP"
                for k, v in template_labels.items():
                    if k not in SELECTOR_LABELS:
                        continue
                    port_u = URIRef(f"{protocol}://{self.ns}/{k}={v}:{port}")
                    yield port_u, RDF.type, K8S.Selector
                    yield port_u, D3F.accesses, s_container
                    yield self.uri, K8S.hasChild, port_u
                    # if template_app:
                    #     yield template_app, NS_K8S.hasChild, port_u

            for env in container.get("env", []):
                try:
                    host_u = parse_url(env["value"])
                    if "." in host_u:
                        host_u = URIRef(f"TCP://{host_u}")
                    else:
                        # host_u is the name of a kubernetes service
                        host_u = self.ns + f"/Service/{host_u}"

                    yield host_u, RDF.type, K8S.Host
                    yield s_container, D3F.accesses, host_u
                except (
                    KeyError,
                    AttributeError,
                    ValueError,  # parse_url
                ):
                    pass


@_register
class ReplicationController(Deployment):
    apiVersion = "v1"
    kind = "ReplicationController"

    def triples(self):
        # OCP ReplicationController is created by a DeploymentConfig.
        if self.metadata.get("annotations", {}).get(
            "openshift.io/deployment-config.name"
        ):
            return
        # A real ReplicationController.
        yield from super().triples()


@_register
class HorizontalPodAutoscaler(K8Resource):
    """
    HorizontalPodAutoscaler
    $.spec.scaleTargetRef
    """

    apiVersion = "autoscaling/v1"
    kind = "HorizontalPodAutoscaler"

    def triple_spec(self):
        if not (scale_target := self.spec.get("scaleTargetRef")):
            return
        kind = scale_target["kind"]
        name = scale_target["name"]
        if kind in ("DeploymentConfig", "Deployment"):
            target_u = URIRef(self.ns + f"/{kind}/{name}")
            yield self.uri, D3F.accesses, target_u
            yield target_u, K8S.hasChild, self.uri
            yield target_u, RDF.type, K8S.Job
            yield self.ns, K8S.hasChild, target_u


@_register
class ReplicaSet(K8Resource):
    """
    ReplicaSet
    $.spec.template.spec.containers[*]
    """

    apiVersion = "apps/v1"
    kind = "ReplicaSet"

    def triples(self):
        # if it's related to a Deployment, skip it.
        if self.metadata.get("ownerReferences", [{}])[0].get("kind") == "Deployment":
            yield from []


@_register
class DeploymentConfig(Deployment):
    apiVersion = "apps.openshift.io/v1"
    kind = "DeploymentConfig"


@_register
class StatefulSet(Deployment):
    apiVersion = "apps/v1"
    kind = "StatefulSet"


@_register
class CronJob(Deployment):
    """
    CronJob
    $.spec.jobTemplate.spec.template.spec.containers[*]
    """

    apiVersion = "batch/v1"
    kind = "CronJob"

    def __init__(self, *a, **k) -> None:
        Deployment.__init__(self, *a, **k)
        self.spec = self.spec["jobTemplate"]["spec"]

    def triples_spec(self):
        yield from super().triple_spec()
        jobs_u = self.ns + "/Jobs"
        yield jobs_u, K8S.hasChild, self.uri
