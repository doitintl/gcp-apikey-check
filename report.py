"""Console and file reporting for scan findings."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from gcp_errors import SkipReason
from models import Finding, Severity, SEVERITY_ORDER
from scanner import ScanResult

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


def _fmt_duration(seconds: float) -> str:
    total = int(round(seconds))
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MED: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

# Inline (non-background) styles for chips and labels.
SEVERITY_TEXT_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MED: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class Report:
    def __init__(self, result: ScanResult, output_dir: str = "."):
        self.result = result
        self.findings = sorted(
            result.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.project_id)
        )
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")

    # ------------------------------------------------------------------ #
    # Console
    # ------------------------------------------------------------------ #

    AI_ENABLED_CHECKS = ("GEMINI_API_ENABLED", "VERTEX_AI_API_ENABLED")

    def print_console(self):
        actionable = [f for f in self.findings if f.severity != Severity.INFO]
        sa_inventory = [f for f in self.findings if f.check_name == "SA_KEY_INVENTORY"]
        ai_enabled = [f for f in self.findings if f.check_name in self.AI_ENABLED_CHECKS]

        console.print()
        self._print_header(actionable, sa_inventory, ai_enabled)
        self._print_coverage()

        if not actionable:
            console.print("\n[bold green]✓ No actionable findings.[/bold green]")
        else:
            self._print_findings_table(actionable)
            self._print_recommendations(actionable)

        if ai_enabled:
            self._print_ai_enabled(ai_enabled)
        if sa_inventory:
            self._print_sa_inventory(sa_inventory)

    def _print_header(
        self, actionable: list[Finding], sa_inventory: list[Finding], ai_enabled: list[Finding]
    ):
        counts = {s: 0 for s in Severity}
        for f in actionable:
            counts[f.severity] += 1

        # Severity chips, e.g.  CRITICAL 2   HIGH 5
        chips = Text()
        any_chip = False
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MED, Severity.LOW):
            if counts[sev]:
                any_chip = True
                chips.append(f" {sev.value} {counts[sev]} ", style=SEVERITY_STYLE[sev])
                chips.append("  ")
        if not any_chip:
            chips.append(" clean ", style="bold white on green")

        meta = Text()
        meta.append("Scope        ", style="dim")
        meta.append(f"{self.result.scope}\n")
        meta.append("Projects     ", style="dim")
        meta.append(f"{self.result.projects_total}   ")
        meta.append("Workers ", style="dim")
        meta.append(f"{self.result.max_workers}   ")
        meta.append("Duration ", style="dim")
        meta.append(_fmt_duration(self.result.duration_s))
        meta.append("\n")
        meta.append("Findings     ", style="dim")
        meta.append(f"{len(actionable)} actionable   ")
        meta.append("AI APIs ", style="dim")
        meta.append(f"{len(ai_enabled)} enabled   ")
        meta.append("SA keys ", style="dim")
        meta.append(f"{len(sa_inventory)} tracked\n\n")

        console.print(Panel(
            Group(meta, chips),
            title="[bold]GCP Security Scan",
            subtitle=f"[dim]{self.timestamp}Z[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
            expand=False,
        ))

    def _print_coverage(self):
        skips = self.result.skips.skips
        if not skips:
            console.print("[green]✓ Coverage:[/green] [dim]all checks completed — results are complete.[/dim]")
            return

        by_reason = self.result.skips.by_reason()
        distinct_scopes = len({s.scope for s in skips})

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow", expand=False)
        table.add_column("Reason", no_wrap=True)
        table.add_column("Count", justify="right", width=7)
        table.add_column("Examples", overflow="fold")

        # Order reasons by frequency, most-skipped first.
        for reason, count in by_reason.most_common():
            examples = ", ".join(self.result.skips.example_scopes(reason, limit=2))
            table.add_column
            table.add_row(reason.value, str(count), Text(examples, style="dim"))

        headline = Text()
        headline.append("⚠ Incomplete coverage — ", style="bold yellow")
        headline.append(
            f"{len(skips)} check(s) across {distinct_scopes} scope(s) could not be completed.\n"
            "Findings below reflect only what was scannable. Re-run with -v for per-scope detail.",
            style="yellow",
        )

        renderables = [headline, Text(), table]

        # "API disabled" almost always means the API isn't enabled on the ADC quota
        # project (calls are billed against it). Turn that into a concrete fix.
        if SkipReason.API_DISABLED in by_reason:
            hint = Text()
            hint.append("Tip: ", style="bold cyan")
            hint.append(
                "'API disabled' usually means the API isn't enabled on your ADC quota project. "
                "Enable it there, or point ADC at a project that has it:\n",
                style="dim",
            )
            hint.append("  gcloud auth application-default set-quota-project PROJECT_ID", style="cyan")
            renderables.append(Text())
            renderables.append(hint)

        console.print(Panel(
            Group(*renderables),
            title="[bold yellow]Scan coverage",
            border_style="yellow",
            box=box.ROUNDED,
            expand=False,
        ))

    def _print_findings_table(self, findings: list[Finding]):
        by_project: dict[str, list[Finding]] = {}
        for f in findings:
            by_project.setdefault(f.project_id, []).append(f)

        console.print()
        console.rule("[bold]Findings", style="cyan")

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

            table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold", expand=False, pad_edge=False)
            table.add_column("#", width=3, justify="right")
            table.add_column("Resource / Check", ratio=1)
            table.add_column("Severity", width=10, no_wrap=True)

            for i, (resource_name, res_findings) in enumerate(sorted_resources, 1):
                max_sev = _max_severity(res_findings)
                label = _display_label(res_findings[0])

                # Resource header row — human-readable label + rolled-up worst severity
                table.add_row(
                    str(i),
                    Text(label, style="bold"),
                    Text(max_sev.value, style=SEVERITY_TEXT_STYLE[max_sev]),
                )
                # One indented sub-row per check, sorted worst-first
                for f in sorted(res_findings, key=lambda f: SEVERITY_ORDER[f.severity]):
                    table.add_row(
                        "",
                        Text(f"  {f.check_name}", style="dim"),
                        Text(f.severity.value, style=SEVERITY_TEXT_STYLE[f.severity]),
                    )

            console.print(table)

    def _print_recommendations(self, findings: list[Finding]):
        console.print()
        console.rule("[bold]Recommendations", style="cyan")

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
                sev_text = Text(f"[{max_sev.value}]", style=SEVERITY_TEXT_STYLE[max_sev])
                console.print(f"\n  {i}. ", end="")
                console.print(sev_text, end=" ")
                console.print(f"[bold]{label}[/bold]")

                # Each check lettered a, b, c…
                for j, f in enumerate(
                    sorted(res_findings, key=lambda f: SEVERITY_ORDER[f.severity]), 1
                ):
                    check_sev = Text(f.severity.value, style=SEVERITY_TEXT_STYLE[f.severity])
                    console.print(f"     {chr(96 + j)}. ", end="")
                    console.print(check_sev, end=" ")
                    console.print(f"[bold]{f.check_name}[/bold]")
                    console.print(f"        {f.description}")
                    console.print(f"        [dim]Fix:[/dim] {f.recommendation}")
                    console.print(f"        [dim]Ref:[/dim] {f.doc_url}")

    def _print_ai_enabled(self, ai_enabled: list[Finding]):
        console.print()
        console.rule("[bold]AI APIs Enabled[/bold] [dim](informational)", style="magenta")

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta", expand=False)
        table.add_column("Project", overflow="fold")
        table.add_column("Enabled API")

        for f in sorted(ai_enabled, key=lambda x: (x.project_id, x.details.get("api_name", ""))):
            api = f.details.get("api_display_name") or f.details.get("api_name", "")
            table.add_row(f.project_id, api)

        console.print(table)

    def _print_sa_inventory(self, inventory: list[Finding]):
        console.print()
        console.rule("[bold dim]Service Account Key Inventory", style="dim")

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

    # ------------------------------------------------------------------ #
    # Files
    # ------------------------------------------------------------------ #

    def save(self, fmt: str):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if fmt in ("json", "both"):
            self._save_json()
        if fmt in ("csv", "both"):
            self._save_csv()

    def _save_json(self):
        path = self.output_dir / f"gcp-security-scan-{self.timestamp}.json"
        payload = {
            "scope": self.result.scope,
            "timestamp": f"{self.timestamp}Z",
            "projects_total": self.result.projects_total,
            "duration_seconds": round(self.result.duration_s, 1),
            "coverage": {
                "complete": self.result.skips.is_empty(),
                "skipped_total": len(self.result.skips.skips),
                "skipped_by_reason": {
                    reason.value: count for reason, count in self.result.skips.by_reason().items()
                },
            },
            "findings": [f.to_dict() for f in self.findings],
        }
        path.write_text(json.dumps(payload, indent=2))
        console.print(f"\n[dim]JSON → {path}[/dim]")

    def _save_csv(self):
        path = self.output_dir / f"gcp-security-scan-{self.timestamp}.csv"

        if not self.findings:
            # Still write a header so downstream tooling gets a valid, non-empty file.
            base_cols = [
                "severity", "project_id", "resource_name", "resource_label",
                "check_name", "description", "recommendation", "doc_url",
            ]
            with open(path, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow(base_cols)
            console.print(f"[dim]CSV  → {path}[/dim]")
            return

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
