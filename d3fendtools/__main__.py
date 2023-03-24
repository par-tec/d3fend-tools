import logging
from pathlib import Path

import click
from rdflib import Graph

from d3fendtools import as_mermaid, kuberdf, mermaidrdf

log = logging.getLogger(__name__)


def _get_resources(basepath, glob_pattern, ignore, match):
    basepath = Path(basepath)
    files = None
    if basepath.is_file():
        files = (basepath,)
    elif basepath.is_dir():
        files = Path(basepath).glob(glob_pattern)

    if ignore:
        files = (f for f in files if not f.match(ignore))
    if match:
        files = (f for f in files if f.match(match))
    files = list(files)
    log.info("Parsing files: %s", files)
    return files


@click.command()
@click.argument("basepath", type=click.Path(exists=True))
@click.argument(
    "destfile",
    type=click.Path(exists=False),
    default="deleteme",
)
@click.option(
    "--resource-type",
    "-t",
    required=True,
    help="Resource type. One possible choiche between kube, oas, mermaid",
    type=click.Choice(["kube", "oas", "mermaid"], case_sensitive=False),
)
@click.option(
    "--ns-from-file",
    default=True,
    is_flag=True,
    help="Use the filename as the namespace",
)
@click.option(
    "--mermaid",
    default=False,
    is_flag=True,
    help="Convert from RDF to Mermaid",
)
@click.option(
    "--ignore",
    default=None,
    help="Ignore files matching this pattern",
)
@click.option(
    "--match",
    default=None,
    help="Select files matching this pattern",
)
def main(basepath, destfile, resource_type, ns_from_file, mermaid, ignore, match):

    if resource_type == "kube":
        resources = _get_resources(basepath, "**/*.y*ml", ignore, match)
        kuberdf_options = dict(ns_from_file=ns_from_file)
        kuberdf.parse_resources(resources, outfile=destfile, **kuberdf_options)
    elif resource_type == "oas":
        raise NotImplementedError
    elif resource_type == "mermaid":
        resources = _get_resources(basepath, "**/*.md", ignore, match)
        mermaidrdf.parse_resources(resources, outfile=destfile)

    if mermaid:
        log.info("Converting to Mermaid")
        g = Graph()
        g.parse(Path(destfile).with_suffix(".ttl"), format="turtle")
        mermaid = as_mermaid.RDF2Mermaid(g)
        mermaid_text = mermaid.render()
        markdown_text = f"# Sample {destfile}\n\n```mermaid\n\n{mermaid_text}\n ```\n"
        Path(destfile).with_suffix(".md").write_text(markdown_text)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
