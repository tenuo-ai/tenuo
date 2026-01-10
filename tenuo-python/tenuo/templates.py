"""
Pre-built warrant templates for common AI agent scenarios.

These templates provide ready-to-use capability patterns that follow
security best practices. Use them directly or as starting points for
customization.

Usage:
    from tenuo import mint
    from tenuo.templates import FileReader, WebSearcher, DatabaseReader

    # Grant read-only access to specific directory
    async with mint(FileReader.in_directory("/data/reports")) as warrant:
        ...

    # Grant web search with allowed domains
    async with mint(WebSearcher.domains(["api.openai.com", "*.google.com"])) as warrant:
        ...
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .constraints import Capability
from tenuo_core import Pattern, Exact, OneOf, Range, Regex, Subpath, UrlSafe  # type: ignore


# =============================================================================
# File System Templates
# =============================================================================


class FileReader:
    """Read-only file access templates.

    All methods use secure Subpath constraint which blocks path traversal
    attacks like "/data/../etc/passwd".
    """

    @staticmethod
    def in_directory(path: str) -> Capability:
        """Read files in a directory (and subdirectories).

        Uses Subpath constraint which normalizes paths before checking,
        blocking path traversal attacks.

        Example:
            async with mint(FileReader.in_directory("/data")) as w:
                read_file("/data/reports/q4.txt")      # ✓ allowed
                read_file("/data/../etc/passwd")       # ✗ BLOCKED (traversal)
                read_file("/etc/passwd")               # ✗ denied
        """
        return Capability("read_file", path=Subpath(path))

    @staticmethod
    def exact_file(path: str) -> Capability:
        """Read a specific file only.

        Example:
            async with mint(FileReader.exact_file("/config/app.json")) as w:
                content = read_file("/config/app.json")  # ✓ allowed
                content = read_file("/config/secrets.json")  # ✗ denied
        """
        return Capability("read_file", path=Exact(path))

    @staticmethod
    def extensions(directory: str, exts: List[str]) -> Capability:
        """Read files with specific extensions in a directory.

        Note: Uses Pattern for glob matching. For maximum security,
        combine with application-level extension validation.

        Example:
            async with mint(FileReader.extensions("/docs", [".md", ".txt"])) as w:
                read_file("/docs/readme.md")  # ✓ allowed
                read_file("/docs/data.json")  # ✗ denied
        """
        # Create pattern for each extension
        patterns = [f"{directory.rstrip('/')}/*{ext}" for ext in exts]
        return Capability("read_file", path=OneOf(patterns))


class FileWriter:
    """Write access templates (use with caution).

    All methods use secure Subpath constraint which blocks path traversal
    attacks like "/tmp/../etc/hosts".
    """

    @staticmethod
    def in_directory(path: str) -> Capability:
        """Write files in a directory (and subdirectories).

        Uses Subpath constraint which normalizes paths before checking,
        blocking path traversal attacks.

        ⚠️ Warning: Write access is sensitive. Prefer narrow paths.

        Example:
            async with mint(FileWriter.in_directory("/tmp/output")) as w:
                write_file("/tmp/output/report.txt", data)  # ✓ allowed
                write_file("/tmp/output/../etc/hosts", d)   # ✗ BLOCKED (traversal)
                write_file("/etc/hosts", data)              # ✗ denied
        """
        return Capability("write_file", path=Subpath(path))

    @staticmethod
    def append_only(path: str) -> Capability:
        """Append to a log file (more restrictive than full write).

        Example:
            async with mint(FileWriter.append_only("/var/log/agent.log")) as w:
                append_file("/var/log/agent.log", entry)  # ✓ allowed
        """
        return Capability("append_file", path=Exact(path))


# =============================================================================
# Database Templates
# =============================================================================


class DatabaseReader:
    """Read-only database access templates."""

    @staticmethod
    def tables(table_names: List[str]) -> Capability:
        """Read from specific tables only.

        Example:
            async with mint(DatabaseReader.tables(["users", "products"])) as w:
                query("SELECT * FROM users")  # ✓ allowed
                query("SELECT * FROM transactions")  # ✗ denied
        """
        return Capability("query", table=OneOf(table_names), operation=Exact("SELECT"))

    @staticmethod
    def schema(schema_name: str) -> Capability:
        """Read from all tables in a schema.

        Example:
            async with mint(DatabaseReader.schema("public")) as w:
                query("SELECT * FROM public.users")  # ✓ allowed
                query("SELECT * FROM private.secrets")  # ✗ denied
        """
        return Capability(
            "query",
            schema=Exact(schema_name),
            operation=Exact("SELECT"),
        )

    @staticmethod
    def with_row_limit(tables: List[str], max_rows: int = 100) -> Capability:
        """Read with row limit to prevent data exfiltration.

        Example:
            async with mint(DatabaseReader.with_row_limit(["users"], max_rows=10)) as w:
                query("SELECT * FROM users LIMIT 10")  # ✓ allowed
                query("SELECT * FROM users")  # ✗ denied (no LIMIT)
        """
        return Capability(
            "query",
            table=OneOf(tables),
            operation=Exact("SELECT"),
            limit=Range(max=max_rows),
        )


class DatabaseWriter:
    """Database write access templates (use with caution)."""

    @staticmethod
    def insert_only(table_names: List[str]) -> Capability:
        """Insert into specific tables (no UPDATE/DELETE).

        Example:
            async with mint(DatabaseWriter.insert_only(["logs", "events"])) as w:
                execute("INSERT INTO logs ...")  # ✓ allowed
                execute("DELETE FROM logs ...")  # ✗ denied
        """
        return Capability(
            "execute",
            table=OneOf(table_names),
            operation=Exact("INSERT"),
        )

    @staticmethod
    def crud(table_names: List[str]) -> Capability:
        """Full CRUD on specific tables.

        ⚠️ Warning: Includes DELETE. Consider insert_only or update_only.
        """
        return Capability(
            "execute",
            table=OneOf(table_names),
            operation=OneOf(["INSERT", "UPDATE", "DELETE"]),
        )


# =============================================================================
# HTTP/API Templates
# =============================================================================


class WebSearcher:
    """Web search and API access templates.

    All methods use UrlSafe constraint which provides SSRF protection:
    - Blocks private IPs (10.x, 172.16.x, 192.168.x)
    - Blocks loopback (127.x, ::1, localhost)
    - Blocks cloud metadata (169.254.169.254)
    - Blocks IP encoding bypasses (decimal, hex, octal, IPv6-mapped)
    """

    @staticmethod
    def domains(allowed: List[str]) -> Capability:
        """Access specific domains only with SSRF protection.

        Supports wildcards: "*.example.com" matches "api.example.com"

        Example:
            async with mint(WebSearcher.domains(["api.openai.com"])) as w:
                fetch("https://api.openai.com/v1/...")   # ✓ allowed
                fetch("https://malicious.com/...")       # ✗ denied
                fetch("http://169.254.169.254/")         # ✗ BLOCKED (SSRF)
        """
        return Capability("http_request", url=UrlSafe(allow_domains=allowed))

    @staticmethod
    def any_public() -> Capability:
        """Access any public URL with SSRF protection.

        Allows any public internet URL but blocks internal/dangerous URLs.

        Example:
            async with mint(WebSearcher.any_public()) as w:
                fetch("https://api.github.com/...")     # ✓ allowed
                fetch("http://169.254.169.254/")        # ✗ BLOCKED (metadata)
                fetch("http://127.0.0.1/")              # ✗ BLOCKED (loopback)
        """
        return Capability("http_request", url=UrlSafe())

    @staticmethod
    def url_pattern(pattern: str) -> Capability:
        """Access URLs matching a pattern.

        Note: Uses Pattern for glob matching. Does not provide SSRF
        protection - use domains() for security-critical applications.

        Example:
            async with mint(WebSearcher.url_pattern("https://api.example.com/v1/*")) as w:
                fetch("https://api.example.com/v1/users")  # ✓ allowed
                fetch("https://api.example.com/v2/users")  # ✗ denied
        """
        return Capability("http_request", url=Pattern(pattern))

    @staticmethod
    def read_only(domains: List[str]) -> Capability:
        """GET requests only to specific domains with SSRF protection.

        Combines domain allowlist + GET-only + SSRF protection.

        Example:
            async with mint(WebSearcher.read_only(["api.news.com"])) as w:
                fetch("GET https://api.news.com/...")   # ✓ allowed
                fetch("POST https://api.news.com/...")  # ✗ denied
                fetch("GET http://169.254.169.254/")    # ✗ BLOCKED (SSRF)
        """
        return Capability(
            "http_request",
            url=UrlSafe(allow_domains=domains),
            method=Exact("GET"),
        )


class ApiClient:
    """API client templates for common services."""

    @staticmethod
    def openai(models: Optional[List[str]] = None) -> Capability:
        """OpenAI API access.

        Example:
            async with mint(ApiClient.openai(models=["gpt-4o"])) as w:
                call_openai(model="gpt-4o")  # ✓ allowed
                call_openai(model="gpt-3.5-turbo")  # ✗ denied
        """
        constraints: Dict[str, Any] = {
            "domain": Exact("api.openai.com"),
        }
        if models:
            constraints["model"] = OneOf(models)
        return Capability("http_request", **constraints)

    @staticmethod
    def anthropic(models: Optional[List[str]] = None) -> Capability:
        """Anthropic API access."""
        constraints: Dict[str, Any] = {
            "domain": Exact("api.anthropic.com"),
        }
        if models:
            constraints["model"] = OneOf(models)
        return Capability("http_request", **constraints)

    @staticmethod
    def internal_api(base_url: str) -> Capability:
        """Internal API access (all endpoints under base URL).

        Example:
            async with mint(ApiClient.internal_api("https://internal.company.com/api/")) as w:
                fetch("https://internal.company.com/api/users")  # ✓ allowed
        """
        return Capability("http_request", url=Pattern(f"{base_url.rstrip('/')}/*"))


# =============================================================================
# Code Execution Templates
# =============================================================================


class CodeRunner:
    """Code execution templates."""

    @staticmethod
    def python_safe() -> Capability:
        """Execute Python with restricted imports.

        Blocks: os, subprocess, socket, ctypes, etc.
        """
        blocked = [
            "os",
            "subprocess",
            "socket",
            "ctypes",
            "multiprocessing",
            "sys",
            "importlib",
            "builtins",
            "__builtins__",
        ]
        return Capability(
            "execute_code",
            language=Exact("python"),
            blocked_imports=OneOf(blocked),
        )

    @staticmethod
    def sandbox(language: str, timeout_ms: int = 5000) -> Capability:
        """Execute code in sandboxed environment.

        Example:
            async with mint(CodeRunner.sandbox("python", timeout_ms=3000)) as w:
                run_code("print('hello')", lang="python")  # ✓ allowed, times out after 3s
        """
        return Capability(
            "execute_code",
            language=Exact(language),
            timeout_ms=Range(max=timeout_ms),
            sandbox=Exact("true"),  # String representation for Rust compatibility
        )


# =============================================================================
# Shell/System Templates
# =============================================================================


class ShellExecutor:
    """Shell command execution templates."""

    @staticmethod
    def allowed_commands(commands: List[str]) -> Capability:
        """Execute only specific shell commands.

        Example:
            async with mint(ShellExecutor.allowed_commands(["ls", "cat", "grep"])) as w:
                run("ls -la")  # ✓ allowed
                run("rm -rf /")  # ✗ denied
        """
        return Capability("shell", command=OneOf(commands))

    @staticmethod
    def read_only_commands() -> Capability:
        """Common read-only shell commands.

        Includes: ls, cat, head, tail, grep, find, wc, du, df, pwd, echo
        """
        safe_commands = [
            "ls",
            "cat",
            "head",
            "tail",
            "grep",
            "find",
            "wc",
            "du",
            "df",
            "pwd",
            "echo",
            "date",
            "hostname",
            "uname",
        ]
        return Capability("shell", command=OneOf(safe_commands))


# =============================================================================
# Email/Messaging Templates
# =============================================================================


class EmailSender:
    """Email sending templates."""

    @staticmethod
    def to_domains(domains: List[str]) -> Capability:
        """Send email to specific domains only.

        Example:
            async with mint(EmailSender.to_domains(["company.com"])) as w:
                send_email("alice@company.com", ...)  # ✓ allowed
                send_email("external@gmail.com", ...)  # ✗ denied
        """
        domain_pattern = "|".join(d.replace(".", r"\.") for d in domains)
        return Capability(
            "send_email",
            to=Regex(f"^[^@]+@({domain_pattern})$"),
        )

    @staticmethod
    def to_recipients(emails: List[str]) -> Capability:
        """Send email to specific recipients only.

        Example:
            async with mint(EmailSender.to_recipients(["admin@co.com", "support@co.com"])) as w:
                send_email("admin@co.com", ...)  # ✓ allowed
        """
        return Capability("send_email", to=OneOf(emails))


# =============================================================================
# Composite Templates (Common Agent Patterns)
# =============================================================================


@dataclass
class AgentTemplate:
    """Composite template combining multiple capabilities."""

    name: str
    description: str
    capabilities: List[Capability]

    def __iter__(self):
        """Allow unpacking: mint(*template)"""
        return iter(self.capabilities)


class CommonAgents:
    """Pre-built templates for common agent patterns.

    All templates use secure constraints:
    - FileReader/FileWriter use Subpath (path traversal protection)
    - WebSearcher uses UrlSafe (SSRF protection)
    """

    @staticmethod
    def research_assistant(
        search_domains: List[str],
        output_dir: str,
    ) -> AgentTemplate:
        """Research assistant that can search web and save findings.

        Args:
            search_domains: Allowed domains for web search
            output_dir: Directory for saving output files

        Example:
            template = CommonAgents.research_assistant(
                search_domains=["scholar.google.com", "arxiv.org"],
                output_dir="/tmp/research",
            )
            async with mint(*template) as w:
                # Agent can search and save, nothing else
                ...
        """
        return AgentTemplate(
            name="research_assistant",
            description="Web search + file output",
            capabilities=[
                WebSearcher.read_only(search_domains),
                FileWriter.in_directory(output_dir),
            ],
        )

    @staticmethod
    def data_analyst(
        tables: List[str],
        output_dir: str,
        max_rows: int = 1000,
    ) -> AgentTemplate:
        """Data analyst that can query DB and write reports.

        Args:
            tables: Allowed database tables
            output_dir: Directory for reports
            max_rows: Maximum rows per query (default: 1000)

        Example:
            template = CommonAgents.data_analyst(
                tables=["sales", "products"],
                output_dir="/reports",
                max_rows=500,
            )
            async with mint(*template) as w:
                # Agent can query limited rows and save reports
                ...
        """
        return AgentTemplate(
            name="data_analyst",
            description="DB read + report generation",
            capabilities=[
                DatabaseReader.with_row_limit(tables, max_rows),
                FileWriter.in_directory(output_dir),
            ],
        )

    @staticmethod
    def code_assistant(
        allowed_dirs: List[str],
        read_only: bool = True,
    ) -> AgentTemplate:
        """Code assistant for reading/editing source code.

        Args:
            allowed_dirs: Directories the agent can access
            read_only: If False, allow writes (default: True)

        Example:
            template = CommonAgents.code_assistant(
                allowed_dirs=["/src", "/tests"],
                read_only=False,  # Allow edits
            )
        """
        capabilities = [FileReader.in_directory(d) for d in allowed_dirs]
        if not read_only:
            capabilities.extend([FileWriter.in_directory(d) for d in allowed_dirs])

        return AgentTemplate(
            name="code_assistant",
            description="Source code access",
            capabilities=capabilities,
        )

    @staticmethod
    def customer_support(
        db_tables: List[str],
        email_domains: List[str],
    ) -> AgentTemplate:
        """Customer support agent with DB lookup and email.

        Example:
            template = CommonAgents.customer_support(
                db_tables=["customers", "orders", "products"],
                email_domains=["company.com"],
            )
        """
        return AgentTemplate(
            name="customer_support",
            description="Customer lookup + email",
            capabilities=[
                DatabaseReader.tables(db_tables),
                EmailSender.to_domains(email_domains),
            ],
        )

    @staticmethod
    def web_agent(
        allowed_domains: Optional[List[str]] = None,
        output_dir: Optional[str] = None,
    ) -> AgentTemplate:
        """Web browsing agent with SSRF protection.

        Args:
            allowed_domains: If set, restrict to these domains.
                             If None, allow any public URL.
            output_dir: If set, allow saving files here.

        Example:
            # Public web access (SSRF-protected)
            template = CommonAgents.web_agent()

            # Restricted to specific domains
            template = CommonAgents.web_agent(
                allowed_domains=["api.github.com"],
                output_dir="/tmp/downloads"
            )
        """
        capabilities: List[Capability] = []

        if allowed_domains:
            capabilities.append(WebSearcher.domains(allowed_domains))
        else:
            capabilities.append(WebSearcher.any_public())

        if output_dir:
            capabilities.append(FileWriter.in_directory(output_dir))

        return AgentTemplate(
            name="web_agent",
            description="Web browsing (SSRF-protected)",
            capabilities=capabilities,
        )


# =============================================================================
# Export
# =============================================================================

__all__ = [
    # File templates
    "FileReader",
    "FileWriter",
    # Database templates
    "DatabaseReader",
    "DatabaseWriter",
    # Web templates
    "WebSearcher",
    "ApiClient",
    # Code/Shell templates
    "CodeRunner",
    "ShellExecutor",
    # Email templates
    "EmailSender",
    # Composite templates
    "AgentTemplate",
    "CommonAgents",
]
