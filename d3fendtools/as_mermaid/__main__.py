from pathlib import Path
from d3fendtools.kuberdf import parse_resources
from d3fendtools.as_mermaid import RDF2Mermaid
from rdflib import Graph
from d3fendtools.as_mermaid.utils import unify_sameas
import logging
import click

logging.basicConfig(
    level=logging.DEBUG,
)


@click.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", help="Output markdown file")
def main(files, output):
    if not files:
        raise click.UsageError("At least one file is required")
    output_md = Path(output)
    resource_paths = []
    for file in files:
        p = Path(file)
        if p.is_file():
            resource_paths.append(p)
        else:
            resource_paths.extend(list(p.glob("**/*.yaml")))

    g: Graph = parse_resources(resource_paths, output_md.with_suffix(".ttl").as_posix())
    g1 = unify_sameas(g=g)
    mermaid = RDF2Mermaid(g1)
    mermaid_text = mermaid.render().splitlines()

    mermaid_text = [
        line for line in mermaid_text if not ("$(" in line or "helm" in line.lower())
    ]

    output_md.write_text("# Foo\n```mermaid\n" + "\n".join(mermaid_text) + "\n```\n")


if __name__ == "__main__":
    main()
