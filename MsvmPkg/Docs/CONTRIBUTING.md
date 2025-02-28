# Contributing to the MsvmPkg

Welcome, and thank you for your interest in contributing to the MsvmPkg!

There are many ways in which you can contribute, beyond writing code. The goal of this document is to provide a
high-level overview of how you can get involved.

## Asking Questions

Have a question? Rather than opening an issue, please post your question under the `Q&A` category in the `Discussions`
section of the the MsvmPkg GitHub repo.

## Reporting Issues

The MsvmPkg repo has an `Issues` section. Bug reports, feature requests, and documentation requests can all be
submitted in the issues section.

## Security Vulnerabilities

Please review the repo's `Security Policy` for more details. The MsvmPkg has `Private vulnerability reporting`
enabled.  Please use the security tab to report a potential issue.

### Look For an Existing Issue

Before you create a new issue, please do a search in the issues section of the repo to see if the issue or
feature request has already been filed.

If you find your issue already exists, make relevant comments and add your
[reaction](https://github.com/blog/2119-add-reactions-to-pull-requests-issues-and-comments). Use a reaction in place
of a "+1" comment:

* 👍 - upvote
* 👎 - downvote

If you cannot find an existing issue that describes your bug or feature, create a new issue using the guidelines below.

### Follow Your Issue

Please continue to follow your request after it is submitted to assist with any additional information that might be
requested.

### Pull Request Best Practices

Pull requests for UEFI code can become large and difficult to review due to the large number of build and
configuration files. To aid maintainers in reviewing your code, we suggest adhering to the following guidelines:

1. Do keep code reviews single purpose; don't add more than one feature at a time.
2. Do fix bugs independently of adding features.
3. Do provide documentation and unit tests.
4. Do introduce code in digestible amounts.
   * If the contribution logically be broken up into separate pull requests that independently build and function
     successfully, do use multiple pull requests.

#### Code Categories

To keep code digestible, you may consider breaking large pull requests into three categories of commits within the pull
request.

1. **Interfaces**: .h, .inf, .dec, documentation
2. **Implementation**: .c, unit tests, unit test build file; unit tests should build and run at this point
3. **Integration/Build**: .dec, .dsc, .fdf, (.yml) configuration files, integration tests; code added to platform and
   affects downstream consumers

By breaking the pull request into these three categories, the pull request reviewers can digest each piece
independently.

If your commits are still very large after adhering to these categories, consider further breaking the pull request
down by library/driver; break each component into its own commit.

#### Implementation Limits

Implementation is ultimately composed of functions as logical units of code.

To help maintainers review the code and improve long-term maintainability, limit functions to 60 lines of code. If your
function exceeds 60 lines of code, it likely has also exceeded a single responsibility and should be broken up.

Files are easier to review and maintain if they contain functions that serves similar purpose. Limit files to around
1,000 lines of code (excluding comments). If your file exceeds 1,000 lines of code, it may have functions that should
be split into separate files.

---

By following these guidelines, your pull requests will be reviewed faster, and you'll avoid being asked to refactor the
code to follow the guidelines.

Feel free to create a draft pull request and ask for suggestions on how to split the pull request if you are unsure.

## Thank You

Thank you for your interest in the MsvmPkg and taking the time to contribute!
