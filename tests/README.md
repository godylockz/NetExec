# nxc Tests
## Running Tests
### Unit Tests
* Install nxc (either in venv or via Poetry)
* Run `pytest` (or `poetry run pytest`)

### End to End Tests
* Install nxc (either in venv or via Poetry): `poetry install --with dev`
* Run `python tests/e2e_tests.py -t $IP -u $USER -p $PASS`, with optional `-k` parameter
  * Poetry: `poetry run python tests/e2e_tests.py -t $IP -u $USER -p $PASS`
* For testing standalone binaries (e.g. windows) run: `python tests/e2e_tests.py --executable dist/nxc.exe -t $IP -u $USER -p $PASS`
* To see full errors (that might show real errors not caught by checking the exit code), run with the `--errors` flag

### Spider Plus fixture

After explicitly authorizing testing on `127.0.0.1`, run:

```sh
uv run --extra spider python tests/spider_plus_fixture.py --check
```

This starts a read-only SMB server on a dynamically assigned loopback port,
creates synthetic documents and credentials, and invokes the real NetExec CLI
with isolated `NXC_PATH` configuration. It checks document extraction, custom
queries, filter boundaries, bounded content reads, downloads, and cached files.
It also checks modification-time output in `--dir` and `--spider`.
The fixture shuts down its server and removes its temporary data on exit.

Add `--ocr` to check a generated image through Tesseract; this requires the local
Tesseract runtime and English language data. The default check disables OCR and
needs no OCR installation. Exact module commands and options are defined in the
fixture runner and recorded in `e2e_commands.txt`.
