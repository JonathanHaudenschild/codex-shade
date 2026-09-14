Scan a file for personal data and credentials without modifying it:

```
shade scan --file $ARGUMENTS
```

The output lists `line / severity / label / masked preview`. Previews are masked
on purpose — real values are never printed.

Report how many findings there are grouped by label, call out anything of
`secret` severity first, and for likely false positives give me the exact
`shade allow '<term>'` command. If the file is one an agent should never open at
all, suggest a glob to add to `deny_paths` in `~/.shade/config.json`.
