# Contributing to Tenuo

Thank you for your interest in contributing to Tenuo! We welcome contributions from the community.

## Development Setup

### Prerequisites

- **Rust**: Latest stable version (install via [rustup](https://rustup.rs/))
- **Python**: 3.9 or higher
- **maturin**: For building Python bindings (`pip install maturin`)

### Setting up the Environment

1.  Clone the repository:
    ```bash
    git clone https://github.com/tenuo/tenuo.git
    cd tenuo
    ```

2.  Create a virtual environment for Python:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r tenuo-python/requirements-dev.txt
    ```

3.  Build the project:
    ```bash
    maturin develop
    ```

## Running Tests

We provide a script to run all checks (formatting, linting, tests, security audit):

```bash
./scripts/check.sh
```

Please ensure this script passes before submitting a Pull Request.

### Running Individual Tests

- **Rust Tests**:
    ```bash
    cargo test
    ```

- **Python Tests**:
    ```bash
    pytest tenuo-python/tests
    ```

## Code Style

- **Rust**: We use `rustfmt`. The check script will verify formatting.
- **Python**: We use `black` and `isort`.

## Pull Request Process

1.  Fork the repository and create your branch from `main`.
2.  If you've added code that should be tested, add tests.
3.  Ensure the test suite passes (`./scripts/check.sh`).
4.  Make sure your code lints.
5.  Issue that pull request!

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
