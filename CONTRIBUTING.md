# Contributing to deadlight-guardian

## Development Process

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue a pull request.

## Any contributions you make will be under the MIT License
When you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project.

## Report bugs using GitHub's [issue tracker]
Report a bug by [opening a new issue]().

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Development Setup

1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the environment: `source venv/bin/activate`
4. Install dependencies: `pip install -e ".[dev]"`
5. Install pre-commit hooks: `guardian hooks install`

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=guardian
```

## Pull Request Process

1. Update the README.md with details of changes if needed.
2. Update the CHANGELOG.md with notes on your changes.
3. The PR will be merged once you have the sign-off of another developer.
