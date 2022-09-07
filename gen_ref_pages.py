"""Generate the code reference pages."""

from pathlib import Path

import mkdocs_gen_files

nav = mkdocs_gen_files.Nav()  # type: ignore[attr-defined]

for path in sorted(Path("starlite_jwt").rglob("*.py")):  #
    module_path = Path("starlite_jwt").with_suffix("")
    doc_path = Path("starlite_jwt").with_suffix(".md")
    full_doc_path = Path("reference", doc_path)

    parts = module_path.parts

    if parts[-1] == "__main__":
        continue
    if parts[-1] == "__init__":
        parts = parts[:-1]
        doc_path = doc_path.with_name("index.md")
        full_doc_path = full_doc_path.with_name("index.md")

    nav[parts] = doc_path.as_posix()

    with mkdocs_gen_files.open(full_doc_path, "w") as fd:
        identifier = ".".join(parts)
        fd.write(f"::: {identifier}")

    mkdocs_gen_files.set_edit_path(full_doc_path, path)

with mkdocs_gen_files.open("reference/SUMMARY.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())
