# Demo Troubleshooting

## Hardhat node never becomes ready

- ensure `contracts/` dependencies are installed
- run `npm run build --prefix contracts`
- check whether another process is already using the chosen port

## HTTP signer service will not start

- confirm `CHAINATTEST_SIGNER_AUTH_TOKEN` is set when starting the service
- confirm the signer policy file exists and contains valid JSON
- inspect `artifacts/demo/signer-audit.jsonl` for rejected requests

## Demo stops during proof generation

- confirm `circuits/` dependencies are installed
- confirm the Groth16 artifacts exist for both circuits
- rerun `python -m unittest discover -s tests` to validate the local proving path

## Submission fails

- inspect `artifacts/demo/state/audit.jsonl`
- inspect `artifacts/demo/state/jobs.json`
- inspect the signer audit log for auth or policy rejection

## Windows-specific issues

- if contract installs fail with a locked native Hardhat binary, run:

```bash
cd contracts
npm run repair
```
