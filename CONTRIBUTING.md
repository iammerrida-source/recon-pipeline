# Contributing

Contributions are welcome! Here's how:

## Reporting Bugs

Open an issue with:
- Command you ran
- Expected vs actual behavior
- Relevant section of `pipeline.log`

## Adding Features

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Test on a domain you have permission to scan
4. Submit a PR with a clear description of what you added and why

## Ideas Welcome

- New passive sources
- Better wildcard detection
- Output format improvements
- Performance optimizations

## Code Style

- Bash only (no external script dependencies beyond the listed tools)
- Every new phase should respect the `--resume` checkpoint system
- All new tool calls must use `has_opt` check and degrade gracefully
- Add timing with `T0=$(ts)` ... `_time "$(fmt_time $(elapsed $T0))"`
