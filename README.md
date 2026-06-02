# apiscout

An aesthetic, all-in-one API security scanner CLI.

```bash
git clone https://github.com/anaselkhettabi/apiscout
cd apiscout
pip install -e .
# headers + fuzzer only
apiscout scan https://petstore.swagger.io

# all 4 modules — headers, spec, live, fuzzer
apiscout scan https://petstore.swagger.io --spec https://petstore.swagger.io/v2/swagger.json

# full scan with verbose output and report export
apiscout scan https://petstore.swagger.io --spec https://petstore.swagger.io/v2/swagger.json --verbose --json results.json --html results.html
```

## Features
- Security header analysis (HSTS, CSP, CORS, X-Content-Type, etc.)
- OpenAPI / Swagger spec static analysis
- Live endpoint probing
- Path fuzzing for common sensitive/debug routes
- JSON + HTML report export
- Exit code 1 on findings — CI-friendly
