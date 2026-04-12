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

## Integration Maintenance

We track upstream API changes in OpenAI, CrewAI, AutoGen, LangChain, and LangGraph via automated CI:

- **Dependabot** (`.github/dependabot.yml`) — weekly dependency update PRs
- **Compatibility matrix** (`.github/workflows/integration-compatibility-matrix.yml`) — tests min + latest versions weekly
- **Release monitor** (`.github/workflows/monitor-upstream-releases.yml`) — daily checks for new upstream releases
- **Smoke tests** (`tenuo-python/tests/integration/test_smoke.py`) — verifies API contracts

### Responding to Breaking Changes

1. Review upstream changelog
2. Run smoke tests: `pytest tests/integration/test_smoke.py -k <integration>`
3. Update integration code if needed
4. Update `docs/compatibility-matrix.md`
5. Test examples
6. Update version constraints in `pyproject.toml` if needed

| Priority | Definition | Response Time |
|----------|------------|---------------|
| **P0** | Blocks users, no workaround | 48 hours |
| **P1** | Workaround exists | 1 week |
| **P2** | Minor impact | Next release |

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
