# CONTRIBUTING

To contribute to this repository, please follow the guidelines below.

## pre-commit

Pre-commit checks your files before committing. It can lint, format or do
other checks on them.

Once you install it via

        pip3 install pre-commit --user

You can run it directly via

        pre-commit run --all-files

Or install it as a pre-commit hook

        pre-commit install

## Making a PR

Contributing to a repository is done via pull requests (PR).
It is important to keep the code base clean and consistent in time,
in order to make it maintanable
and reduce unuseful deployments (see [CI](#ci)).

A correct development process, with code reviews, is part of a correct
shift-left strategy.

Following this procedure will help you to make a clean PR.
Each pull request should be associated with an issue and a branch.

1. If there's no issue for your PR, create one where you describe the expected behavior and the current behavior;
1. If you are not a member of the organization, fork the repository and fetch from both your fork and the origin

        GH=ioggstream  # use your github username
        git clone -o par-tec https://github.com/par-tec/python-cookiecutter
        cd python-cookiecutter
        git remote add origin git@github.com:$GH/python-cookiecutter.git

1. Create a branch for your PR fetching from the main branch, using your username and issue-number as branch name.
   Before checkout, make sure you have the latest version of the `par-tec/main` branch.

        ISSUE=123  # use the issue number
        git fetch --all
        git checkout -b $GH-$ISSUE par-tec/main

1. Make your changes (this includes [pre-commit checks](#pre-commit)) and review them when adding.
   This is an important and overlooked step, especially when
   you are working alone or on a large PR. Moreover this allows you to split your changes in multiple commits
   or to discard some of changes that you still want to temporarily keep in your working directory.

        git add -p

1. You can now commit them. If your PR fixes the issue, the commit message should start with `Fix: #ISSUE` where `ISSUE` is the issue number.
   Otherwise, a reference to the issue can be added in the commit message body.

        git add .
        git commit -m "Fix: #$ISSUE"

## CI

Each PR is tested by a CI workflow that runs on GitHub Actions.
The final step might include a deployment to PyPI or to an OCI image registry.
