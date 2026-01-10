"""
Tests for tenuo.templates - Pre-built capability templates.

Tests cover:
- File templates (FileReader, FileWriter)
- Database templates (DatabaseReader, DatabaseWriter)
- Web/API templates (WebSearcher, ApiClient)
- Code/Shell templates (CodeRunner, ShellExecutor)
- Email templates (EmailSender)
- Composite templates (CommonAgents)
"""

from tenuo.templates import (
    FileReader,
    FileWriter,
    DatabaseReader,
    DatabaseWriter,
    WebSearcher,
    ApiClient,
    CodeRunner,
    ShellExecutor,
    EmailSender,
    AgentTemplate,
    CommonAgents,
)
from tenuo.constraints import Capability
from tenuo_core import Exact, OneOf, Pattern, Range, Regex, Subpath, UrlSafe


class TestFileReader:
    """Test FileReader templates."""

    def test_in_directory(self):
        """FileReader.in_directory creates Subpath capability."""
        cap = FileReader.in_directory("/data/reports")

        assert isinstance(cap, Capability)
        assert cap.tool == "read_file"
        assert "path" in cap.constraints
        assert isinstance(cap.constraints["path"], Subpath)

    def test_in_directory_blocks_traversal(self):
        """FileReader.in_directory blocks path traversal."""
        cap = FileReader.in_directory("/data")
        subpath = cap.constraints["path"]

        assert subpath.contains("/data/file.txt")
        assert not subpath.contains("/data/../etc/passwd")
        assert not subpath.contains("/etc/passwd")

    def test_exact_file(self):
        """FileReader.exact_file creates Exact constraint."""
        cap = FileReader.exact_file("/config/app.json")

        assert cap.tool == "read_file"
        assert isinstance(cap.constraints["path"], Exact)
        assert cap.constraints["path"].value == "/config/app.json"

    def test_extensions(self):
        """FileReader.extensions creates OneOf with patterns."""
        cap = FileReader.extensions("/docs", [".md", ".txt"])

        assert cap.tool == "read_file"
        assert isinstance(cap.constraints["path"], OneOf)
        values = cap.constraints["path"].values
        assert "/docs/*.md" in values
        assert "/docs/*.txt" in values


class TestFileWriter:
    """Test FileWriter templates."""

    def test_in_directory(self):
        """FileWriter.in_directory creates Subpath capability."""
        cap = FileWriter.in_directory("/tmp/output")

        assert cap.tool == "write_file"
        assert isinstance(cap.constraints["path"], Subpath)

    def test_in_directory_blocks_traversal(self):
        """FileWriter.in_directory blocks path traversal."""
        cap = FileWriter.in_directory("/tmp/output")
        subpath = cap.constraints["path"]

        assert subpath.contains("/tmp/output/file.txt")
        assert not subpath.contains("/tmp/output/../etc/hosts")

    def test_append_only(self):
        """FileWriter.append_only creates append capability."""
        cap = FileWriter.append_only("/var/log/agent.log")

        assert cap.tool == "append_file"
        assert isinstance(cap.constraints["path"], Exact)


class TestDatabaseReader:
    """Test DatabaseReader templates."""

    def test_tables(self):
        """DatabaseReader.tables creates correct constraints."""
        cap = DatabaseReader.tables(["users", "products"])

        assert cap.tool == "query"
        assert isinstance(cap.constraints["table"], OneOf)
        assert "users" in cap.constraints["table"].values
        assert "products" in cap.constraints["table"].values
        assert isinstance(cap.constraints["operation"], Exact)
        assert cap.constraints["operation"].value == "SELECT"

    def test_schema(self):
        """DatabaseReader.schema restricts to schema."""
        cap = DatabaseReader.schema("public")

        assert cap.tool == "query"
        assert cap.constraints["schema"].value == "public"
        assert cap.constraints["operation"].value == "SELECT"

    def test_with_row_limit(self):
        """DatabaseReader.with_row_limit adds Range constraint."""
        cap = DatabaseReader.with_row_limit(["users"], max_rows=100)

        assert cap.tool == "query"
        assert isinstance(cap.constraints["limit"], Range)
        assert cap.constraints["limit"].max == 100


class TestDatabaseWriter:
    """Test DatabaseWriter templates."""

    def test_insert_only(self):
        """DatabaseWriter.insert_only restricts to INSERT."""
        cap = DatabaseWriter.insert_only(["logs", "events"])

        assert cap.tool == "execute"
        assert isinstance(cap.constraints["operation"], Exact)
        assert cap.constraints["operation"].value == "INSERT"

    def test_crud(self):
        """DatabaseWriter.crud allows all CRUD operations."""
        cap = DatabaseWriter.crud(["products"])

        assert cap.tool == "execute"
        assert isinstance(cap.constraints["operation"], OneOf)
        ops = cap.constraints["operation"].values
        assert "INSERT" in ops
        assert "UPDATE" in ops
        assert "DELETE" in ops


class TestWebSearcher:
    """Test WebSearcher templates."""

    def test_domains(self):
        """WebSearcher.domains uses UrlSafe constraint."""
        cap = WebSearcher.domains(["api.example.com"])

        assert cap.tool == "http_request"
        assert isinstance(cap.constraints["url"], UrlSafe)

    def test_domains_blocks_ssrf(self):
        """WebSearcher.domains blocks SSRF attacks."""
        cap = WebSearcher.domains(["api.example.com"])
        url_safe = cap.constraints["url"]

        # SSRF vectors should be blocked
        assert not url_safe.is_safe("http://169.254.169.254/")
        assert not url_safe.is_safe("http://127.0.0.1/")
        assert not url_safe.is_safe("http://10.0.0.1/")

    def test_any_public(self):
        """WebSearcher.any_public allows any public URL."""
        cap = WebSearcher.any_public()

        assert cap.tool == "http_request"
        url_safe = cap.constraints["url"]
        assert isinstance(url_safe, UrlSafe)

        # Public should work
        assert url_safe.is_safe("https://api.github.com/")

        # SSRF should be blocked
        assert not url_safe.is_safe("http://169.254.169.254/")

    def test_url_pattern(self):
        """WebSearcher.url_pattern uses Pattern."""
        cap = WebSearcher.url_pattern("https://api.example.com/v1/*")

        assert cap.tool == "http_request"
        assert isinstance(cap.constraints["url"], Pattern)

    def test_read_only(self):
        """WebSearcher.read_only combines UrlSafe + GET-only."""
        cap = WebSearcher.read_only(["api.news.com"])

        assert cap.tool == "http_request"
        assert isinstance(cap.constraints["url"], UrlSafe)
        assert cap.constraints["method"].value == "GET"


class TestApiClient:
    """Test ApiClient templates."""

    def test_openai_default(self):
        """ApiClient.openai with no model restriction."""
        cap = ApiClient.openai()

        assert cap.tool == "http_request"
        assert cap.constraints["domain"].value == "api.openai.com"
        assert "model" not in cap.constraints

    def test_openai_with_models(self):
        """ApiClient.openai with model restriction."""
        cap = ApiClient.openai(models=["gpt-4o", "gpt-4o-mini"])

        assert isinstance(cap.constraints["model"], OneOf)
        assert "gpt-4o" in cap.constraints["model"].values

    def test_anthropic(self):
        """ApiClient.anthropic targets Anthropic domain."""
        cap = ApiClient.anthropic()

        assert cap.constraints["domain"].value == "api.anthropic.com"

    def test_internal_api(self):
        """ApiClient.internal_api creates URL pattern."""
        cap = ApiClient.internal_api("https://internal.company.com/api/")

        assert isinstance(cap.constraints["url"], Pattern)
        assert "internal.company.com/api/*" in cap.constraints["url"].pattern


class TestCodeRunner:
    """Test CodeRunner templates."""

    def test_python_safe(self):
        """CodeRunner.python_safe blocks dangerous imports."""
        cap = CodeRunner.python_safe()

        assert cap.tool == "execute_code"
        assert cap.constraints["language"].value == "python"
        blocked = cap.constraints["blocked_imports"].values
        assert "os" in blocked
        assert "subprocess" in blocked

    def test_sandbox(self):
        """CodeRunner.sandbox adds timeout."""
        cap = CodeRunner.sandbox("python", timeout_ms=3000)

        assert cap.tool == "execute_code"
        assert cap.constraints["timeout_ms"].max == 3000
        # Note: sandbox=Exact(True) doesn't work with Rust Exact constraint
        # So we just verify the timeout is set correctly


class TestShellExecutor:
    """Test ShellExecutor templates."""

    def test_allowed_commands(self):
        """ShellExecutor.allowed_commands restricts to list."""
        cap = ShellExecutor.allowed_commands(["ls", "cat", "grep"])

        assert cap.tool == "shell"
        assert isinstance(cap.constraints["command"], OneOf)
        assert "ls" in cap.constraints["command"].values
        assert "rm" not in cap.constraints["command"].values

    def test_read_only_commands(self):
        """ShellExecutor.read_only_commands provides safe defaults."""
        cap = ShellExecutor.read_only_commands()

        commands = cap.constraints["command"].values
        assert "ls" in commands
        assert "cat" in commands
        assert "grep" in commands
        # Should not include dangerous commands
        assert "rm" not in commands
        assert "chmod" not in commands


class TestEmailSender:
    """Test EmailSender templates."""

    def test_to_domains(self):
        """EmailSender.to_domains creates regex for domains."""
        cap = EmailSender.to_domains(["company.com", "partner.org"])

        assert cap.tool == "send_email"
        assert isinstance(cap.constraints["to"], Regex)

    def test_to_recipients(self):
        """EmailSender.to_recipients uses OneOf."""
        cap = EmailSender.to_recipients(["alice@co.com", "bob@co.com"])

        assert cap.tool == "send_email"
        assert isinstance(cap.constraints["to"], OneOf)
        assert "alice@co.com" in cap.constraints["to"].values


class TestAgentTemplate:
    """Test AgentTemplate composite structure."""

    def test_iteration(self):
        """AgentTemplate can be unpacked."""
        template = AgentTemplate(
            name="test",
            description="Test template",
            capabilities=[
                FileReader.in_directory("/data"),
                FileWriter.in_directory("/output"),
            ],
        )

        caps = list(template)
        assert len(caps) == 2
        assert caps[0].tool == "read_file"
        assert caps[1].tool == "write_file"

    def test_unpacking_syntax(self):
        """Can use *template syntax."""
        template = AgentTemplate(
            name="test",
            description="Test",
            capabilities=[FileReader.in_directory("/data")],
        )

        # Should work with *template
        caps = [*template]
        assert len(caps) == 1


class TestCommonAgents:
    """Test CommonAgents pre-built templates."""

    def test_research_assistant(self):
        """CommonAgents.research_assistant combines search + write."""
        template = CommonAgents.research_assistant(
            search_domains=["arxiv.org", "scholar.google.com"],
            output_dir="/tmp/research",
        )

        assert template.name == "research_assistant"
        assert len(template.capabilities) == 2

        # First should be web search
        web_cap = template.capabilities[0]
        assert web_cap.tool == "http_request"

        # Second should be file write
        file_cap = template.capabilities[1]
        assert file_cap.tool == "write_file"

    def test_data_analyst(self):
        """CommonAgents.data_analyst combines DB read + file write."""
        template = CommonAgents.data_analyst(
            tables=["sales", "products"],
            output_dir="/reports",
            max_rows=500,
        )

        assert template.name == "data_analyst"
        caps = list(template)

        # Check DB capability has row limit
        db_cap = caps[0]
        assert db_cap.tool == "query"
        assert db_cap.constraints["limit"].max == 500

    def test_code_assistant_read_only(self):
        """CommonAgents.code_assistant in read-only mode."""
        template = CommonAgents.code_assistant(
            allowed_dirs=["/src", "/tests"],
            read_only=True,
        )

        caps = list(template)
        # Should only have read capabilities
        assert all(c.tool == "read_file" for c in caps)
        assert len(caps) == 2

    def test_code_assistant_read_write(self):
        """CommonAgents.code_assistant with write access."""
        template = CommonAgents.code_assistant(
            allowed_dirs=["/src"],
            read_only=False,
        )

        caps = list(template)
        tools = [c.tool for c in caps]
        assert "read_file" in tools
        assert "write_file" in tools

    def test_customer_support(self):
        """CommonAgents.customer_support combines DB + email."""
        template = CommonAgents.customer_support(
            db_tables=["customers", "orders"],
            email_domains=["company.com"],
        )

        caps = list(template)
        tools = [c.tool for c in caps]
        assert "query" in tools
        assert "send_email" in tools


class TestSecurityConstraints:
    """Test that all templates use secure constraints by default."""

    def test_file_reader_uses_subpath(self):
        """FileReader.in_directory uses Subpath (path traversal protection)."""
        cap = FileReader.in_directory("/data")
        subpath = cap.constraints["path"]

        assert isinstance(subpath, Subpath)
        assert subpath.contains("/data/file.txt")
        assert not subpath.contains("/data/../etc/passwd")

    def test_file_writer_uses_subpath(self):
        """FileWriter.in_directory uses Subpath (path traversal protection)."""
        cap = FileWriter.in_directory("/tmp/output")
        subpath = cap.constraints["path"]

        assert isinstance(subpath, Subpath)
        assert subpath.contains("/tmp/output/report.txt")
        assert not subpath.contains("/tmp/output/../etc/hosts")

    def test_web_searcher_uses_url_safe(self):
        """WebSearcher.domains uses UrlSafe (SSRF protection)."""
        cap = WebSearcher.domains(["api.github.com"])
        url_safe = cap.constraints["url"]

        assert isinstance(url_safe, UrlSafe)
        assert url_safe.is_safe("https://api.github.com/repos")
        assert not url_safe.is_safe("http://169.254.169.254/")  # SSRF blocked

    def test_common_agents_research_uses_secure(self):
        """CommonAgents.research_assistant uses secure constraints."""
        template = CommonAgents.research_assistant(
            search_domains=["arxiv.org"],
            output_dir="/tmp/research",
        )

        caps = list(template)
        assert isinstance(caps[0].constraints["url"], UrlSafe)
        assert isinstance(caps[1].constraints["path"], Subpath)

    def test_common_agents_code_uses_secure(self):
        """CommonAgents.code_assistant uses Subpath."""
        template = CommonAgents.code_assistant(["/src"], read_only=False)

        for cap in template.capabilities:
            assert isinstance(cap.constraints["path"], Subpath)

    def test_common_agents_web_uses_secure(self):
        """CommonAgents.web_agent uses UrlSafe."""
        template = CommonAgents.web_agent()

        caps = list(template)
        assert isinstance(caps[0].constraints["url"], UrlSafe)


class TestTemplatesWithMint:
    """Integration tests - templates work with mint()."""

    def test_template_with_mint_sync(self):
        """Templates can be used with mint_sync."""
        from tenuo import configure, mint_sync, SigningKey
        from tenuo.config import reset_config

        reset_config()
        key = SigningKey.generate()
        configure(issuer_key=key, dev_mode=True, audit_log=False)

        # Use a template
        cap = FileReader.in_directory("/data")

        with mint_sync(cap):
            # Context is set, warrant should be active
            pass  # Just verify no errors

    def test_composite_template_with_mint_sync(self):
        """Composite templates can be unpacked into mint_sync."""
        from tenuo import configure, mint_sync, SigningKey
        from tenuo.config import reset_config

        reset_config()
        key = SigningKey.generate()
        configure(issuer_key=key, dev_mode=True, audit_log=False)

        template = CommonAgents.research_assistant(
            search_domains=["example.com"],
            output_dir="/tmp",
        )

        # Unpack template into mint
        with mint_sync(*template):
            pass  # Just verify no errors

    def test_web_agent_template_with_mint_sync(self):
        """Web agent templates work with mint_sync."""
        from tenuo import configure, mint_sync, SigningKey
        from tenuo.config import reset_config

        reset_config()
        key = SigningKey.generate()
        configure(issuer_key=key, dev_mode=True, audit_log=False)

        # Use web agent template
        template = CommonAgents.web_agent()

        with mint_sync(*template):
            pass  # Just verify no errors

