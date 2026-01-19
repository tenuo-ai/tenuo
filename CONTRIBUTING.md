# Contributing to Tenuo

Thank you for your interest in contributing to Tenuo! We welcome contributions from the community.

## Development Setup

### Prerequisites

- **Rust**: Latest stable version (install via [rustup](https://rustup.rs/))
- **Python**: 3.9 or higher
- **maturin**: For building Python bindings (`uv pip install maturin`)

### Setting up the Environment

1.  Clone the repository:
    ```bash
    git clone https://github.com/tenuo-ai/tenuo.git
    cd tenuo
    ```

2.  Create a virtual environment for Python:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    # Install uv (fast package installer)
    pip install uv
    uv pip install -e ".[dev]"
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

## Building Integrations

If you're adding support for a new framework (e.g., LlamaIndex, AutoGPT):

- Review the [Python Integration Guide](tenuo-python/docs/integration-guide.md) for required API patterns and invariant tests
- Study existing integrations: [OpenAI](tenuo-python/tenuo/openai.py), [ADK](tenuo-python/tenuo/google_adk/guard.py), [LangChain](tenuo-python/tenuo/integrations/langchain.py)
- Ensure all runtime authorization uses Rust core via wire format
- Test against the 6 core invariants (monotonic attenuation, fail-closed, expiry, etc.)

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

By contributing, you agree that your contributions will be licensed under the project's [MIT OR Apache-2.0 License](LICENSE).
