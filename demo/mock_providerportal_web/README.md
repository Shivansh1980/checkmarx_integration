# Mock Provider Portal Web

This project is intentionally vulnerable and exists only for the mock Checkmarx demo flow.

Files that the mock scan points to:

- `package.json`
- `package-lock.json`
- `Dockerfile`
- `src/server.js`

Reset the project back to the vulnerable baseline with:

```bash
python tools/mock_demo_project.py reset
```

If Copilot changes the dependencies or Dockerfile during a demo, run that command to restore the original vulnerable files.