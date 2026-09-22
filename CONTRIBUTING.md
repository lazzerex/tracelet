# Contributing to Tracelet

Thank you for your interest in contributing to Tracelet.

Tracelet is a Linux observability tool built with Rust and eBPF. It collects and displays system activity, including process execution, file opens, TCP connections, and syscall latency.

Contributions are welcome, whether they involve bug fixes, documentation, performance improvements, testing, or new observability features.

## Before You Start

Before making changes:

1. Read the README to understand the project architecture and supported features.
2. Search existing issues and pull requests to avoid duplicate work.
3. For significant feature changes, open an issue first to discuss the proposed approach.
4. Keep changes focused and avoid unrelated modifications.

Please read and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Environment

Tracelet is developed for Linux and requires the Rust and eBPF toolchain.

### Requirements

- Linux
- Rust toolchain `1.98.0`
- Cargo
- Clang
- LLVM
- libelf development headers
- libbpf development headers
- pkg-config
- Linux kernel headers

A compatible kernel with BTF and the required tracing capabilities is needed for live eBPF tracing.

## Getting Started

Clone the repository:

    git clone https://github.com/lazzerex/tracelet.git
    cd tracelet

Build the project:

    cargo build

Run the test suite:

    cargo test --workspace

Build a release binary:

    cargo build --release

## Development Workflow

1. Fork the repository if you are working from an external fork.
2. Clone your fork locally.
3. Create a dedicated branch for your changes.
4. Implement and test your changes.
5. Run the relevant formatting, linting, and test checks.
6. Commit your changes using a clear commit message.
7. Push your branch and open a pull request.

Example:

    git checkout -b feat/add-process-filter

## Code Quality

Before submitting a pull request, run the following checks where applicable:

### Formatting

    cargo fmt --all -- --check

To apply formatting:

    cargo fmt --all

### Linting

    cargo clippy --workspace -- -D warnings

### Tests

    cargo test --workspace

### Build

    cargo build --release

### Security Checks

    cargo deny check all

Tracelet's CI workflow runs formatting, Clippy, tests, release builds, CLI checks, and dependency security auditing.

Please ensure your changes pass the relevant checks before opening a pull request.

## eBPF Development

Tracelet contains both userspace Rust code and kernel-side eBPF programs written in C.

When modifying eBPF programs:

- Ensure the program passes the eBPF verifier.
- Keep event structures consistent between kernel-side code and Rust decoding.
- Validate event sizes before decoding data.
- Consider ring buffer usage and event drop behavior.
- Avoid unnecessary work in frequently executed kernel hooks.
- Test filtering behavior where applicable.
- Document kernel-specific limitations or assumptions.

Changes to kernel-side programs should be reviewed alongside their corresponding userspace collectors and event decoding logic.

## Testing Live Tracing

Some functionality requires elevated privileges or specific kernel capabilities.

Live tracing may require:

- Root privileges or appropriate capabilities.
- Access to the tracing filesystem.
- A kernel with the required BTF and tracepoint support.
- The required Clang, LLVM, and libbpf dependencies.

The CI workflow validates compilation and userspace tests. Live eBPF runtime behavior should also be tested on a compatible Linux environment when relevant.

Do not assume that a successful userspace build guarantees that live tracing will work on every kernel.

## Performance Contributions

Tracelet is an observability tool, so performance and resource usage matter.

For performance-related changes:

- Explain the problem being addressed.
- Describe the measurement methodology.
- Compare against a baseline where possible.
- Include the workload and environment used for benchmarking.
- Avoid presenting results from one machine as universal performance guarantees.

Use the existing benchmark scripts when they are applicable.

## Commit Messages

Use clear and descriptive commit messages.

The following Conventional Commits-style prefixes are recommended:

- `feat:` New functionality
- `fix:` Bug fixes
- `docs:` Documentation changes
- `refactor:` Code restructuring without intended behavior changes
- `test:` Test changes
- `perf:` Performance improvements
- `chore:` Maintenance changes
- `ci:` Continuous integration changes

Examples:

    feat: add syscall filter
    fix: validate event payload size
    docs: update latency measurement guide
    perf: reduce collector allocation overhead
    ci: update Rust toolchain

## Pull Requests

Before opening a pull request:

- Ensure the change has a clear purpose.
- Keep the pull request focused.
- Update documentation when behavior or usage changes.
- Add or update tests where applicable.
- Explain important implementation decisions.
- Include relevant benchmark results for performance changes.
- Mention any limitations or environment-specific requirements.

Pull request descriptions should include:

### Summary

Describe what changed and why.

### Testing

List the commands and tests you ran.

### Environment

For kernel or eBPF-related changes, include relevant Linux kernel and toolchain information.

### Limitations

Describe any known limitations, untested scenarios, or follow-up work.

## Bug Reports

When reporting a bug, include:

- Operating system and Linux kernel version.
- Tracelet version or commit.
- Rust and Clang versions where relevant.
- The command being executed.
- Steps to reproduce the issue.
- Expected behavior.
- Actual behavior.
- Relevant logs or error messages.

Remove sensitive information before sharing logs or system details.

## Feature Requests

Feature requests are welcome.

Please explain:

- The problem the feature would solve.
- The proposed behavior.
- Why the feature fits Tracelet's scope.
- Any kernel, performance, or compatibility considerations.

For substantial changes, discuss the design in an issue before implementation.

## Code of Conduct

By participating in this project, you agree to follow the project's [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing to Tracelet, you agree that your contributions will be licensed under the same license as the project.
