# Guidelines

To contribute code changes or update the documentation, please follow these steps:

1. Fork the upstream repository and clone the fork locally.
2. Install [poetry](https://python-poetry.org/), and install the project's dependencies with `poetry install`.
3. Install [pre-commit](https://pre-commit.com/) and install the hooks by running `pre-commit install` in the
   repository's hook.
4. Make whatever changes and additions you wish and commit these - please try to keep your commit history clean.
5. Create a pull request to the main repository with an explanation of your changes. The PR should detail the
   contribution and link to any related issues - if existing.

## Docs

### Docs Theme and Appearance

We welcome contributions that enhance / improve the appearance and usability of the docs, as well as any images, icons
etc.

We use the excellent [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) theme, which comes with a lot
of options out of the box. If you wish to contribute to the docs style / setup, or static site generation, you should
consult the theme docs as a first step.

### Running the Docs Locally

To run the docs locally, simply use the `docker-compose` configuration in place by executing `docker compose up`.
On the first run it will pull and build the image, but afterwards this should be quite fast.

Note: if you want your terminal back use `docker compose up --detach` but then you will need to bring the docs down
with `docker compose down` rather than ctrl+C.

### Writing and Editing Docs

We welcome contributions that enhance / improve the content of the docs. Feel free to add examples, clarify text,
restructure the docs etc. But make sure to follow these emphases:

- the docs should be as simple and easy to grasp as possible.
- the docs should be written in good idiomatic english.
- examples should be simple and clear.
- provide links where applicable.
- provide diagrams where applicable and possible.
