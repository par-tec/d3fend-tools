from pathlib import Path

import click
from rdflib import Graph

from . import MermaidRDF, extract_mermaid, filter_mermaid, flip_mermaid, parse_mermaid


@click.command()
@click.argument(
    "operation",
    type=click.Choice(["r2m", "m2r", "m2m"]),
)
@click.argument("basepath", type=click.Path(exists=True))
@click.argument(
    "destfile",
    type=click.Path(exists=False),
    default="deleteme.ttl",
)
@click.option(
    "--match",
    default=None,
    help="Filter by this pattern",
)
@click.option(
    "--flip",
    default=False,
    is_flag=True,
    help="Flip the direction of the graph",
)
def main(operation, basepath, destfile, match, flip):
    if operation == "r2m":
        rdf_to_mermaid(basepath, destfile)
        exit(0)
    if operation == "m2r":
        mermaid_to_rdf(basepath, destfile)
        exit(0)

    if operation == "m2m":
        if not (match or flip):
            raise ValueError("Must specify either match or flip")
        text_mmd = Path(basepath).read_text()
        text_mmd = filter_mermaid(text_mmd, match)
        if flip:
            text_mmd = flip_mermaid(text_mmd)
        Path(destfile).write_text(text_mmd)
        exit(0)


def rdf_to_mermaid(basepath, destfile="deleteme.mmd"):
    files = (
        (Path(basepath),)
        if basepath.endswith(".ttl")
        else Path(basepath).glob("**/*.ttl")
    )
    for f in files:
        g = Graph()
        g.parse(f, format="turtle")
        mermaid = MermaidRDF(g)
        mermaid_text = mermaid.render()
        Path(destfile).write_text(mermaid_text)


def mermaid_to_rdf(basepath, destfile):
    turtle = ""
    files = (
        (Path(basepath),)
        if basepath.endswith(".md")
        else Path(basepath).glob("**/*.md")
    )
    for f in files:
        mermaid_graphs = extract_mermaid(f.read_text())
        for graph in mermaid_graphs:
            turtle += "\n" + parse_mermaid(graph)
    Path(destfile).write_text(turtle)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
