# apiscout

An aesthetic, all-in-one API security scanner CLI.

```bash
git clone https://github.com/anaselkhettabi/apiscout
cd apiscout
pip install -e .
apiscout scan https://api.example.com
apiscout scan https://api.example.com --spec openapi.yaml --verbose --html report.html
```

## Features
- Security header analysis (HSTS, CSP, CORS, X-Content-Type, etc.)
- OpenAPI / Swagger spec static analysis
- Live endpoint probing
- Path fuzzing for common sensitive/debug routes
- JSON + HTML report export
- Exit code 1 on findings — CI-friendly
