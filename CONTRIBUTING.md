# Contributing to VSM
We love your input! We want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## We Develop with Github
We use github to host code, to track issues and feature requests, as well as accept pull requests.

## We Use [Github Flow](https://guides.github.com/introduction/flow/index.html), So All Code Changes Happen Through Pull Requests
Pull requests are the best way to propose changes to the codebase (we use [Github Flow](https://guides.github.com/introduction/flow/index.html)). We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. Format and lint the Rust code: `cargo fmt --check` and
   `cargo clippy --all-targets -- -D warnings` (or `npm run lint`, which runs
   both). CI enforces these; fix warnings instead of suppressing them.
3. Run the unit tests: `cargo test` (also `npm run test:unit`).
4. If your change affects the running service, run the black-box HTTP
   integration suite against the stack. `npm test` runs
   `cargo test --test integration -- --ignored` with its `pretest`/`posttest`
   hooks managing the compose stack and Terraform fixtures; start the release
   binary yourself first and point the suite at it:

   ```sh
   cargo build --release
   ./target/release/vsm &
   VSM_BASE_URL=http://localhost:3000 npm test
   ```

5. Issue that pull request!

## Any contributions you make will be under the Apache 2.0 License
In short, when you submit code changes, your submissions are understood to be under the same [Apache 2.0 License](https://choosealicense.com/licenses/apache-2.0/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using Github's [issues](https://github.com/Kronus-Lab/vsm/issues)
We use GitHub issues to track public bugs. Report a bug by [opening a new issue](); it's that easy!

Please write bug reports with detail and background

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

People *love* thorough bug reports. I'm not even kidding.

## Use a Consistent Coding Style
Rust code is formatted with `cargo fmt` and checked with `cargo clippy
--all-targets -- -D warnings` in CI; run `cargo fmt` before committing. Keep
modules small and follow the existing patterns in `src/` and `src/web/`.
Cypress specs follow the style of `cypress/e2e/vsm.cy.js`. Dependency licenses
and advisories are checked with `npm run license` (`cargo deny check licenses`)
and `npm run audit` (`cargo audit`).

## License
By contributing, you agree that your contributions will be licensed under its Apache 2.0 License.

## References
This document was adapted from the open-source contribution guidelines for [Facebook's Draft](https://github.com/facebook/draft-js/blob/a9316a723f9e918afde44dea68b5f9f39b7d9b00/CONTRIBUTING.md)
