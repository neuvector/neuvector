# Contributing Guideline

Thanks for contributing to the project!

Please review and follow the [Code of Conduct](https://github.com/neuvector/neuvector/blob/main/CODE_OF_CONDUCT.md).

Contributing to the project is not limited to writing the code or submitting the PR. We will also appreciate if you can file issues, provide feedback and suggest new features.

Of course, contributing the code is more than welcome!  To keep things simple, if you're fixing a small issue, you can simply submit a PR and we will pick it up. However, if you're planning to submit a bigger PR to implement a new feature or fix a relatively complex bug, please open an issue that explains the change and the motivation for it. If you're addressing a bug, please explain how to reproduce it.

## Repositories

Open Zero Trust project contains the following repositories.

Repository | URL | Description
-----------|-----|-------------
openzerotrust | [https://github.com/neuvector/neuvector](https://github.com/neuvector/neuvector) | This repository hosts the controller and enforcer source code.
manager | [https://github.com/neuvector/manager](https://github.com/neuvector/manager) | The repository for the admin console UI interface.
scanner | [https://github.com/neuvector/scanner](https://github.com/neuvector/scanner) | The repository for the vulnerability scanner.

## Opening PRs and organizing commits

PRs should generally address only 1 issue at a time. If you need to fix two bugs, open two separate PRs. This will keep the scope of your pull requests smaller and allow them to be reviewed and merged more quickly.

When possible, fill out as much detail in the pull request as is reasonable. Explain main design considerations and behavior changes when adequate. Refer to the Jira case or the GitHub issue that you are addressing with the PR.

Generally, pull requests should consist of a single logical commit. However, if your PR is for a large feature, you may need a more logical breakdown of commits. This is fine as long as each commit is a single logical unit.

The other exception to this single-commit rule is if your PR includes a change to a vendored dependency or generated code. To make reviewing easier, these changes should be segregated into their own commit.

### Reviewing and merging

Generally, pull requests need at least one approvals from maintainers to be merged.

Once a PR has the necessary approvals, it can be merged. Here’s how the merge should be handled:
- If the PR is a single logical commit, the merger should use the “Rebase and merge” option. This keeps the git commit history very clean and simple and eliminates noise from "merge commits."
- If the PR is more than one logical commit, the merger should use the “Create a merge commit” option.
- If the PR consists of more than one commit because the author added commits to address feedback, the commits should be squashed into a single commit (or more than one logical commit, if it is a big feature that needs more commits). This can be achieved in one of two ways:
  - The merger can use the “Squash and merge” option. If they do this, the merger is responsible for cleaning up the commit message according to the previously stated commit message guidance.
  - The pull request author, after getting the requisite approvals, can reorganize the commits as they see fit (using, for example, git rebase -i) and re-push.
