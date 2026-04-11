from pathlib import Path

import typer

app = typer.Typer(help="ChainAttest CLI scaffold.")


@app.command("register-attestation")
def register_attestation(
    model: Path,
    metadata: Path,
    training: Path,
    dataset: Path,
) -> None:
    typer.echo(
        f"Scaffold only: register attestation for model={model} metadata={metadata} training={training} dataset={dataset}"
    )


@app.command("register-eval-claim")
def register_eval_claim(attestation_id: int, threshold_bps: int) -> None:
    typer.echo(
        f"Scaffold only: register eval claim for attestation_id={attestation_id} threshold_bps={threshold_bps}"
    )


@app.command("prove-eval-threshold")
def prove_eval_threshold(attestation_id: int, exact_score: int, threshold_bps: int) -> None:
    typer.echo(
        f"Scaffold only: prove eval threshold for attestation_id={attestation_id} exact_score={exact_score} threshold_bps={threshold_bps}"
    )


@app.command("relay-attestation")
def relay_attestation(attestation_id: int) -> None:
    typer.echo(f"Scaffold only: relay attestation_id={attestation_id}")


@app.command("query-attestation")
def query_attestation(attestation_id: int) -> None:
    typer.echo(f"Scaffold only: query attestation_id={attestation_id}")


if __name__ == "__main__":
    app()

