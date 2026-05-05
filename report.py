"""Console and file reporting for scan findings."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

from models import Finding, Severity, SEVERITY_ORDER

console = Console()


def _max_severity(findings: list[Finding]) -> Severity:
    return min(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity


def _display_label(f: Finding) -> str:
    """Human-readable label for the Resource column in the console table.

    Priority: API key display name → SA email → last path segment of resource_name.
    resource_name itself is always preserved unchanged in the output files.
    """
    if name := f.details.get("display_name"):
        return name
    if email := f.details.get("sa_email"):
        return email
    last = f.resource_name.split("/")[-1]
    return last or f.resource_name


SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MED: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class Report:
    def __init__(self, findings: list[Finding], output_dir: str = "."):
        self.findings = sorted(
            findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.project_id)
        )
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")

    def print_console(self):
        actionable = [f for f in self.findings if f.severity != Severity.INFO]
        inventory = [f for f in self.findings if f.severity == Severity.INFO]

        self._print_summary(actionable, inventory)

        if not actionable:
            console.print("\n[green]No actionable findings.[/green]")
        else:
            self._print_findings_table(actionable)
            self._print_recommendations(actionable)

        if inventory:
            self._print_sa_inventory(inventory)

    def _print_summary(self, actionable: list[Finding], inventory: list[Finding]):
        counts = {s: 0 for s in Severity}
        for f in actionable:
            counts[f.severity] += 1

        console.print("\n" + "━" * 70)
        console.print("[bold]GCP Security Scan — Results[/bold]")
        console.print("━" * 70)

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MED, Severity.LOW]:
            if counts[sev]:
                label = Text(f"  {sev.value:<10}", style=SEVERITY_STYLE[sev])
                console.print(label, end="")
                console.print(f"{counts[sev]} finding(s)")

        total = sum(counts.values())
        console.print(f"\n  Total findings : {total}")
        console.print(f"  SA keys tracked: {len(inventory)}")

    def _print_findings_table(self, findings: list[Finding]):
        by_project: dict[str, list[Finding]] = {}
        for f in findings:
            by_project.setdefault(f.project_id, []).append(f)

        for project_id, project_findings in by_project.items():
            console.print(f"\n[bold underline]Project / Scope: {project_id}[/bold underline]\n")

            # Group checks by resource, sort resources by their worst severity
            by_resource: dict[str, list[Finding]] = {}
            for f in project_findings:
                by_resource.setdefault(f.resource_name, []).append(f)

            sorted_resources = sorted(
                by_resource.items(),
                key=lambda item: SEVERITY_ORDER[_max_severity(item[1])],
            )

            table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold", expand=False)
            table.add_column("Severity", width=10, no_wrap=True)
            table.add_column("#", width=3, justify="right")
            table.add_column("Resource / Check", width=55)
            table.add_column("Sev", width=10, no_wrap=True)

            for i, (resource_name, res_findings) in enumerate(sorted_resources, 1):
                max_sev = _max_severity(res_findings)
                label = _display_label(res_findings[0])

                # Resource header row — highest severity + human-readable label
                table.add_row(
                    Text(max_sev.value, style=SEVERITY_STYLE[max_sev]),
                    str(i),
                    Text(label, style="bold"),
                    "",
                )
                # One indented sub-row per check, sorted worst-first
                for f in sorted(res_findings, key=lambda f: SEVERITY_ORDER[f.severity]):
                    table.add_row(
                        "",
                        "",
                        Text(f"  {f.check_name}", style="dim"),
                        Text(f.severity.value, style=SEVERITY_STYLE[f.severity]),
                    )

            console.print(table)

    def _print_recommendations(self, findings: list[Finding]):
        console.print("\n[bold]Recommendations[/bold]")
        console.print("─" * 70)

        by_project: dict[str, list[Finding]] = {}
        for f in findings:
            by_project.setdefault(f.project_id, []).append(f)

        for project_id, project_findings in by_project.items():
            if len(by_project) > 1:
                console.print(f"\n[dim]── {project_id} ──[/dim]")

            by_resource: dict[str, list[Finding]] = {}
            for f in project_findings:
                by_resource.setdefault(f.resource_name, []).append(f)

            sorted_resources = sorted(
                by_resource.items(),
                key=lambda item: SEVERITY_ORDER[_max_severity(item[1])],
            )

            for i, (resource_name, res_findings) in enumerate(sorted_resources, 1):
                max_sev = _max_severity(res_findings)
                label = _display_label(res_findings[0])

                # Resource header
                sev_text = Text(f"[{max_sev.value}]", style=SEVERITY_STYLE[max_sev])
                console.print(f"\n  {i}. ", end="")
                console.print(sev_text, end=" ")
                console.print(f"[bold]{label}[/bold]")

                # Each check lettered a, b, c…
                for j, f in enumerate(
                    sorted(res_findings, key=lambda f: SEVERITY_ORDER[f.severity]), 1
                ):
                    check_sev = Text(f.severity.value, style=SEVERITY_STYLE[f.severity])
                    console.print(f"     {chr(96 + j)}. ", end="")
                    console.print(check_sev, end=" ")
                    console.print(f"[bold]{f.check_name}[/bold]")
                    console.print(f"        {f.description}")
                    console.print(f"        [dim]Fix:[/dim] {f.recommendation}")
                    console.print(f"        [dim]Ref:[/dim] {f.doc_url}")

    def _print_sa_inventory(self, inventory: list[Finding]):
        console.print("\n[bold]Service Account Key Inventory[/bold]")
        console.print("─" * 70)

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        table.add_column("SA Email", overflow="fold")
        table.add_column("Key ID", width=20, no_wrap=True)
        table.add_column("Age (days)", justify="right", width=10)
        table.add_column("Last Used", width=14)
        table.add_column("Project", width=25)

        for f in inventory:
            d = f.details
            age = str(d.get("age_days", "?"))
            last_used = str(d.get("last_used", "unknown"))
            table.add_row(
                d.get("sa_email", ""),
                d.get("key_id", ""),
                age,
                last_used,
                f.project_id,
            )

        console.print(table)

    def save(self, fmt: str):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if fmt in ("json", "both"):
            self._save_json()
        if fmt in ("csv", "both"):
            self._save_csv()

    def _save_json(self):
        path = self.output_dir / f"gcp-security-scan-{self.timestamp}.json"
        path.write_text(json.dumps([f.to_dict() for f in self.findings], indent=2))
        console.print(f"\n[dim]JSON → {path}[/dim]")

    def _save_csv(self):
        path = self.output_dir / f"gcp-security-scan-{self.timestamp}.csv"

        # Collect all possible field names across all findings
        all_keys: list[str] = []
        seen: set[str] = set()
        for f in self.findings:
            for k in f.to_dict():
                if k not in seen:
                    all_keys.append(k)
                    seen.add(k)

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=all_keys, extrasaction="ignore")
            writer.writeheader()
            for finding in self.findings:
                row = finding.to_dict()
                # Flatten list/dict values for CSV compatibility
                for k, v in row.items():
                    if isinstance(v, (list, dict)):
                        row[k] = json.dumps(v)
                writer.writerow(row)

        console.print(f"[dim]CSV  → {path}[/dim]")
