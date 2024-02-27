import logging
from pathlib import Path
from typing import List

import click
from rdflib import Graph

from d3fendtools import as_mermaid, kuberdf, mermaidrdf

log = logging.getLogger(__name__)


def _get_resources(basepath, glob_pattern, ignore, match) -> List[Path]:
    basepath = Path(basepath)
    files = None
    if basepath.is_file():
        files = (basepath,)
    elif basepath.is_dir():
        files = Path(basepath).glob(glob_pattern)
    else:
        return []

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
    default="/dev/stdout",
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
    "--format",
    default="turtle",
    help="Destination format",
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
def main(basepath, destfile, resource_type, ns_from_file, format, ignore, match):

    if resource_type == "kube":
        resources = _get_resources(basepath, "**/*.y*ml", ignore, match)
        kuberdf_options = dict(ns_from_file=ns_from_file)
        kuberdf.parse_resources(resources, outfile=destfile, **kuberdf_options)
    elif resource_type == "oas":
        raise NotImplementedError
    elif resource_type == "mermaid":
        resources: List[Path] = _get_resources(basepath, "**/*.md", ignore, match)

        if format == "markdown":
            dm = (
                mermaidrdf.D3fendMermaid(resource.read_text()) for resource in resources
            )
            mermaid_text = "\n\n".join(dm.text for dm in dm)
            Path(destfile).write_text(mermaid_text)
        elif format == "turtle":
            mermaidrdf.parse_resources(resources, outfile=destfile)
        else:
            raise NotImplementedError(f"Format {format} not implemented")

    if format == "mermaid":
        log.info("Converting to Mermaid")
        g = Graph()
        g.parse(Path(destfile).with_suffix(".ttl"), format="turtle")
        mermaid = as_mermaid.RDF2Mermaid(g)
        mermaid_text = mermaid.render()
        markdown_text = f"# Sample {destfile}\n\n```mermaid\n\n{mermaid_text}\n ```\n"
        Path(destfile).with_suffix(".md").write_text(markdown_text)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
