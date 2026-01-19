# Contributing to Lockbox

Thank you for your interest in contributing to Lockbox! I appreciate your help in improving this developer and automation-friendly password manager with end-to-end encryption.

## Where to Contribute

**Important**: All contributions (Merge Requests, Issues) are only accepted on my GitLab instance. GitHub is maintained as a read-only mirror.

- **GitLab Repository**: https://gitlab.cherkaoui.ch/HadiCherkaoui/lockbox
- **GitHub Mirror**: https://github.com/HadiCherkaoui/lockbox (read-only)

If you're viewing this on GitHub, please submit your contributions on my GitLab instance instead. Any Issues or Pull Requests opened on GitHub will be politely requested to be ported over to GitLab, or closed.

## Setting Up GitLab Account

If you don't have a GitLab account, you can register on my GitLab instance. Once registered, you can request access to contribute to the project. I will review and approve account creation requests.

## Development Setup

### Prerequisites
- Rust 2024 edition
- Cargo package manager

### Getting Started
1. Fork the repository on GitLab
2. Clone your fork:
   ```bash
   git clone https://gitlab.cherkaoui.ch/YOUR_USERNAME/lockbox.git
   ```
3. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature/my-feature
   ```

### Building the Project
```bash
# Build all workspace members
cargo build

# Build release version
cargo build --release
```

### Running Tests
```bash
# Run all tests in workspace
cargo test

# Run tests for specific crate
cargo test -p lockbox-crypto
cargo test -p lockbox-auth
```

## Code Standards

- Follow Rust idioms and best practices
- Write tests for new functionality
- Ensure all tests pass before submitting
- Run `cargo fmt` to format your code
- Run `cargo clippy` to catch common mistakes and improve code quality

## Types of Contributions

I welcome various types of contributions:

- Bug reports and fixes
- Feature implementations
- Documentation improvements
- Performance optimizations
- Security enhancements

## Submitting Changes

1. Ensure your code follows the project's style and conventions
2. Add tests for any new functionality
3. Update documentation as needed
4. Submit a Merge Request on GitLab

## Questions?

If you have any questions about contributing, feel free to reach out by opening an Issue on my GitLab repository.

Thank you for helping make Lockbox better!
