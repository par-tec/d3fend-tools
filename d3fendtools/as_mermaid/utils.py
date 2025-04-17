from rdflib import Graph, RDF, OWL
from d3fendtools.kuberdf import NS_K8S


class UnionFind:
    """Basic union-find for gathering owl:sameAs equivalences."""

    def __init__(self):
        self.parent = {}

    def find(self, x):
        if self.parent.setdefault(x, x) != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[ry] = rx


def unify_sameas(
    g: Graph | None = None, input_data: str | None = None, format="turtle"
):
    if input_data:
        g = Graph()
        g.parse(data=input_data, format=format)

    if not g:
        raise ValueError("Either a graph or input data must be provided.")

    # 2. Find equivalences with union-find
    uf = UnionFind()
    for s, p, o in g.triples((None, OWL.sameAs, None)):
        uf.union(s, o)

    # Build sets from union-find
    eq_classes = {}
    for x in set(uf.parent.keys()):
        root = uf.find(x)
        eq_classes.setdefault(root, set()).add(x)

    # 3. Create a new graph to store transformed triples
    new_g = Graph()

    # For each resource belonging to no equivalence class, treat them as is
    eq_members = {elem for group in eq_classes.values() for elem in group}

    # 4. Assign a new "union" node for each equivalence class
    #    (Here we just name them all :union; for multiple sameAs sets use counters, etc.)
    union_nodes = {}
    index = 0
    for root, members in eq_classes.items():
        index += 1
        union_node = (
            NS_K8S["union"] if len(eq_classes) == 1 else NS_K8S[f"union{index}"]
        )
        union_nodes[root] = (union_node, members)

    for s, p, o in g:
        # Skip owl:sameAs itself in the output
        if p == OWL.sameAs:
            continue

        # Identify union node for subject/object if they exist
        s_root = uf.find(s) if s in eq_members else None
        o_root = uf.find(o) if o in eq_members else None

        # Replace s or o with the union node if they belong to an equivalence class
        union_subj = union_nodes[s_root][0] if s_root in union_nodes else s
        union_obj = union_nodes[o_root][0] if o_root in union_nodes else o

        # Add the triple (including modifications) to new graph
        new_g.add((union_subj, p, union_obj))

    # 5. For each equivalence class, add :hasChild relationships
    #    and replicate type relationships on the union node
    for root, (union_node, members) in union_nodes.items():
        for m in members:
            new_g.add((union_node, NS_K8S.hasChild, m))
            # Copy the type triple: if m a T, also union a T
            for _, p, t in g.triples((m, RDF.type, None)):
                new_g.add((union_node, RDF.type, t))

    return new_g
