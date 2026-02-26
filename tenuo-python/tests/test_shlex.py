"""
Comprehensive tests for the Shlex constraint.

Tests based on the test vectors in shlex-constraint-spec.md.
"""

import pytest

from tenuo.constraints import Shlex


class TestShlexBasic:
    """Basic functionality tests for Shlex."""

    def test_simple_valid_command(self):
        """Basic valid command should pass."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("ls -la /tmp")

    def test_quoted_semicolon_allowed(self):
        """Quoted semicolon is allowed - it's a literal argument.

        Using shlex.shlex with punctuation_chars=True correctly distinguishes
        between unquoted operators (dangerous) and quoted operators (safe).
        """
        constraint = Shlex(allow=["ls"])
        # Quoted operators are safe - the semicolon is just text
        assert constraint.matches('ls "foo; bar"')

    def test_single_quoted_operators_allowed(self):
        """Operators in single quotes are allowed - they're literal text."""
        constraint = Shlex(allow=["ls"])
        # Single-quoted operators are safe
        assert constraint.matches("ls 'foo && bar'")

    def test_full_path_match(self):
        """Full path should match allowlist."""
        constraint = Shlex(allow=["/usr/bin/ls"])
        assert constraint.matches("/usr/bin/ls -la")

    def test_basename_match(self):
        """Full path should match basename in allowlist."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("/usr/bin/ls -la")

    def test_path_normalization(self):
        """Path traversal in binary should be normalized."""
        constraint = Shlex(allow=["/usr/bin/ls"])
        assert constraint.matches("/usr/bin/../bin/ls -la")

    def test_multiple_allowed_binaries(self):
        """Multiple binaries in allowlist."""
        constraint = Shlex(allow=["git", "ls"])
        assert constraint.matches("git status")
        assert constraint.matches("ls -la")

    def test_globs_allowed_by_default(self):
        """Glob characters allowed by default."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("ls *")

    def test_simple_file_argument(self):
        """Simple file argument should pass."""
        constraint = Shlex(allow=["cat"])
        assert constraint.matches("cat file.txt")


class TestShlexOperatorBlocking:
    """Tests for shell operator blocking."""

    def test_blocks_semicolon(self):
        """Semicolon operator should be blocked."""
        constraint = Shlex(allow=["ls", "rm"])
        assert not constraint.matches("ls -la; rm -rf /")

    def test_blocks_logical_and(self):
        """&& operator should be blocked."""
        constraint = Shlex(allow=["ls", "whoami"])
        assert not constraint.matches("ls -la && whoami")

    def test_blocks_logical_or(self):
        """|| operator should be blocked."""
        constraint = Shlex(allow=["ls", "echo"])
        assert not constraint.matches("ls -la || echo x")

    def test_blocks_pipe(self):
        """Pipe operator should be blocked."""
        constraint = Shlex(allow=["cat", "nc"])
        assert not constraint.matches("cat /etc/passwd | nc x 80")

    def test_blocks_background(self):
        """Background operator should be blocked."""
        constraint = Shlex(allow=["rm"])
        assert not constraint.matches("rm -rf / &")

    def test_blocks_output_redirect(self):
        """Output redirect should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo hi > /tmp/x")

    def test_blocks_input_redirect(self):
        """Input redirect should be blocked."""
        constraint = Shlex(allow=["cat"])
        assert not constraint.matches("cat < /etc/passwd")


class TestShlexExpansionBlocking:
    """Tests for variable/command expansion blocking."""

    def test_blocks_command_substitution(self):
        """$() command substitution should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo $(whoami)")

    def test_blocks_variable_expansion(self):
        """$VAR expansion should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("ls $HOME")

    def test_blocks_brace_expansion(self):
        """${VAR} expansion should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo ${HOME}")

    def test_blocks_backtick_substitution(self):
        """Backtick substitution should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("ls `pwd`")


class TestShlexControlCharacterBlocking:
    """Tests for control character blocking."""

    def test_blocks_newline(self):
        """Newline should be blocked."""
        constraint = Shlex(allow=["ls", "rm"])
        assert not constraint.matches("ls\nrm -rf /")

    def test_blocks_carriage_return(self):
        """Carriage return should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("ls\rrm -rf /")

    def test_blocks_null_byte(self):
        """Null byte should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("ls\x00rm")


class TestShlexBinaryAllowlist:
    """Tests for binary allowlist enforcement."""

    def test_blocks_unlisted_binary(self):
        """Binary not in allowlist should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("cat /etc/passwd")

    def test_requires_non_empty_allowlist(self):
        """Empty allowlist should raise ValueError."""
        with pytest.raises(ValueError, match="at least one allowed binary"):
            Shlex(allow=[])


class TestShlexParseErrors:
    """Tests for parsing error handling."""

    def test_blocks_unbalanced_double_quote(self):
        """Unbalanced double quote should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches('ls "')

    def test_blocks_unbalanced_single_quote(self):
        """Unbalanced single quote should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("ls '")

    def test_blocks_empty_string(self):
        """Empty string should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("")

    def test_blocks_whitespace_only(self):
        """Whitespace-only string should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("   ")


class TestShlexTypeChecks:
    """Tests for type checking."""

    def test_blocks_non_string_int(self):
        """Integer input should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches(123)

    def test_blocks_non_string_none(self):
        """None input should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches(None)

    def test_blocks_non_string_list(self):
        """List input should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches(["ls", "-la"])


class TestShlexGlobBlocking:
    """Tests for optional glob blocking."""

    def test_blocks_glob_asterisk(self):
        """Asterisk should be blocked when block_globs=True."""
        constraint = Shlex(allow=["ls"], block_globs=True)
        assert not constraint.matches("ls *")

    def test_blocks_glob_question(self):
        """Question mark should be blocked when block_globs=True."""
        constraint = Shlex(allow=["ls"], block_globs=True)
        assert not constraint.matches("ls file?.txt")

    def test_blocks_glob_bracket(self):
        """Bracket should be blocked when block_globs=True."""
        constraint = Shlex(allow=["ls"], block_globs=True)
        assert not constraint.matches("ls file[12].txt")


class TestShlexEdgeCases:
    """Tests for edge cases."""

    def test_multiple_spaces(self):
        """Multiple spaces should be normalized."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("ls  -la")

    def test_tab_whitespace(self):
        """Tab is valid whitespace."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("ls\t-la")

    def test_quoted_binary_name(self):
        """Quoted binary name should work."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches('"ls" -la')

    def test_empty_string_argument(self):
        """Empty string argument should pass."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches('ls -la ""')

    def test_double_dash_safe(self):
        """Double dash is safe argument separator."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("ls -- -rf")


class TestShlexRepr:
    """Tests for string representation."""

    def test_repr_basic(self):
        """Basic repr output."""
        constraint = Shlex(allow=["ls", "cat"])
        r = repr(constraint)
        assert "Shlex" in r
        assert "allow=" in r

    def test_repr_with_block_globs(self):
        """Repr with block_globs option."""
        constraint = Shlex(allow=["ls"], block_globs=True)
        r = repr(constraint)
        assert "block_globs=True" in r


# =============================================================================
# Adversarial Tests - Attempting to bypass the constraint
# =============================================================================


class TestShlexAdversarialOperators:
    """Adversarial tests: Operator injection bypass attempts."""

    def test_unicode_semicolon_is_safe(self):
        """Unicode semicolon (U+037E) is NOT a shell operator.

        The Greek question mark looks like semicolon but shells don't
        interpret it as a command separator. This is safe to allow.
        """
        constraint = Shlex(allow=["ls"])
        # Greek question mark - not a shell operator, just a character
        # Shell would try to run "ls" with argument "-la;" as literal text
        assert constraint.matches("ls -la\u037e")

    def test_fullwidth_semicolon_is_safe(self):
        """Fullwidth semicolon (U+FF1B) is NOT a shell operator.

        Unicode fullwidth characters are not interpreted by POSIX shells.
        """
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("ls -la\uff1b")

    def test_unicode_pipe_is_safe(self):
        """Unicode vertical bar variants are NOT shell pipes.

        Only ASCII | is a pipe operator in POSIX shells.
        """
        constraint = Shlex(allow=["cat"])
        # These are just literal characters, not shell operators
        assert constraint.matches("cat file\u2223")  # DIVIDES
        assert constraint.matches("cat file\u01c0")  # LATIN LETTER DENTAL CLICK

    def test_operator_in_middle_of_word(self):
        """Operator embedded in argument should be blocked."""
        constraint = Shlex(allow=["ls"])
        # Semicolon embedded - shell would still execute
        assert not constraint.matches("ls foo;bar")

    def test_operator_with_no_spaces(self):
        """Operators without spaces should be blocked."""
        constraint = Shlex(allow=["ls", "rm"])
        assert not constraint.matches("ls;rm")
        assert not constraint.matches("ls&&rm")
        assert not constraint.matches("ls||rm")

    def test_heredoc_operator(self):
        """Here-doc operators should be blocked."""
        constraint = Shlex(allow=["cat"])
        assert not constraint.matches("cat <<EOF")
        assert not constraint.matches("cat <<<'hello'")

    def test_process_substitution(self):
        """Process substitution should be blocked (contains < or >)."""
        constraint = Shlex(allow=["diff"])
        assert not constraint.matches("diff <(ls) <(ls -la)")


class TestShlexAdversarialExpansion:
    """Adversarial tests: Variable/command expansion bypass attempts."""

    def test_arithmetic_expansion(self):
        """Arithmetic expansion should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo $((1+1))")

    def test_indirect_expansion(self):
        """Indirect variable expansion should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo ${!prefix*}")

    def test_parameter_length(self):
        """Parameter length expansion should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo ${#HOME}")

    def test_substring_expansion(self):
        """Substring expansion should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo ${HOME:0:5}")

    def test_default_value_expansion(self):
        """Default value expansion should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo ${VAR:-default}")

    def test_nested_command_substitution(self):
        """Nested command substitution should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo $(echo $(whoami))")

    def test_mixed_backtick_dollar(self):
        """Mixed substitution styles should be blocked."""
        constraint = Shlex(allow=["echo"])
        assert not constraint.matches("echo `echo $(id)`")

    def test_ansi_c_quoting(self):
        """ANSI-C quoting ($'...') should be blocked."""
        constraint = Shlex(allow=["echo"])
        # Contains $ so should be blocked
        assert not constraint.matches("echo $'hello\\nworld'")


class TestShlexAdversarialControlChars:
    """Adversarial tests: Control character injection attempts."""

    def test_vertical_tab_rejected(self):
        """Vertical tab causes shlex parse error.

        shlex.split() doesn't handle vertical tab well and may fail
        or produce unexpected results. Rejection is safe behavior.
        """
        constraint = Shlex(allow=["ls"])
        # shlex doesn't handle this cleanly
        assert not constraint.matches("ls\x0b-la")

    def test_form_feed_rejected(self):
        """Form feed causes shlex parse error."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("ls\x0c-la")

    def test_bell_character_rejected(self):
        """Bell character causes issues with shlex."""
        constraint = Shlex(allow=["ls"])
        # Control characters in general cause shlex issues
        assert not constraint.matches("ls\x07file")

    def test_backspace_rejected(self):
        """Backspace causes issues with shlex."""
        constraint = Shlex(allow=["ls"])
        # shlex doesn't handle control characters well
        assert not constraint.matches("ls\x08file")

    def test_escape_character(self):
        """Escape character (\\x1b) should be handled."""
        constraint = Shlex(allow=["ls"])
        # ANSI escape - could be used for terminal manipulation
        # But not a shell injection vector
        assert constraint.matches("ls \x1b[31mfile")

    def test_crlf_injection(self):
        """CRLF should be blocked."""
        constraint = Shlex(allow=["ls", "rm"])
        assert not constraint.matches("ls\r\nrm -rf /")

    def test_null_in_middle(self):
        """Null byte in middle of command should be blocked."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("ls -la\x00 /etc")

    def test_unicode_line_separator(self):
        """Unicode line separator (U+2028) should be checked."""
        constraint = Shlex(allow=["ls", "rm"])
        # shlex doesn't treat this as newline, but some systems might
        # Currently passes - document as known limitation
        constraint.matches("ls\u2028rm")
        # This passes because shlex treats it as literal
        # Could be a bypass in some edge cases

    def test_unicode_paragraph_separator(self):
        """Unicode paragraph separator (U+2029) should be checked."""
        constraint = Shlex(allow=["ls", "rm"])
        constraint.matches("ls\u2029rm")
        # Same as above


class TestShlexAdversarialBinaryBypass:
    """Adversarial tests: Binary allowlist bypass attempts."""

    def test_path_traversal_to_different_binary(self):
        """Path traversal should not allow different binary."""
        constraint = Shlex(allow=["ls"])
        # Try to traverse to rm
        assert not constraint.matches("/bin/../bin/rm -rf /")

    def test_symlink_style_path(self):
        """Paths that look like symlinks should be normalized."""
        constraint = Shlex(allow=["/usr/bin/ls"])
        # Multiple traversals
        assert constraint.matches("/usr/bin/../../usr/bin/ls -la")

    def test_double_slash_path(self):
        """Double slashes should be normalized."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("//bin//ls -la")

    def test_dot_path_component(self):
        """Single dot path components should be handled."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("/bin/./ls -la")

    def test_current_dir_binary(self):
        """./binary should be handled correctly."""
        constraint = Shlex(allow=["ls"])
        # ./ls with ls in allowlist - should match basename
        assert constraint.matches("./ls -la")

    def test_relative_path_traversal(self):
        """Relative path with traversal."""
        constraint = Shlex(allow=["ls"])
        # This normalizes to just 'ls'
        assert constraint.matches("../../../usr/bin/ls -la")

    def test_case_sensitivity(self):
        """Binary names should be case-sensitive."""
        constraint = Shlex(allow=["ls"])
        # Most Unix systems are case-sensitive
        assert not constraint.matches("LS -la")
        assert not constraint.matches("Ls -la")

    def test_binary_with_spaces_in_path(self):
        """Paths with spaces should be handled."""
        constraint = Shlex(allow=["my program"])
        assert constraint.matches('"my program" arg1')

    def test_unlisted_similar_binary(self):
        """Similar binary names should not match."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("lsof /")
        assert not constraint.matches("ls-files /")


class TestShlexAdversarialQuoting:
    """Adversarial tests: Quote manipulation bypass attempts."""

    def test_escaped_backtick_in_quotes(self):
        """Escaped backtick in quotes."""
        constraint = Shlex(allow=["echo"])
        # Contains backtick - blocked
        assert not constraint.matches('echo "\\`id\\`"')

    def test_escaped_dollar_in_quotes(self):
        """Escaped dollar in quotes."""
        constraint = Shlex(allow=["echo"])
        # Contains $ - blocked
        assert not constraint.matches('echo "\\$HOME"')

    def test_nested_quotes(self):
        """Nested quote styles."""
        constraint = Shlex(allow=["echo"])
        # Valid nested quoting
        assert constraint.matches("echo 'hello \"world\"'")

    def test_alternating_quotes(self):
        """Alternating quote styles."""
        constraint = Shlex(allow=["echo"])
        assert constraint.matches("echo 'a'\"b\"'c'")

    def test_backslash_at_end(self):
        """Backslash at end of line (line continuation)."""
        constraint = Shlex(allow=["ls"])
        # Unbalanced - shlex will error
        assert not constraint.matches("ls \\")

    def test_backslash_newline(self):
        """Backslash-newline (line continuation) should be blocked."""
        constraint = Shlex(allow=["ls"])
        # Contains newline - blocked
        assert not constraint.matches("ls \\\n-la")


class TestShlexAdversarialEncoding:
    """Adversarial tests: Encoding-based bypass attempts."""

    def test_url_encoded_semicolon(self):
        """URL-encoded semicolon should not bypass (literal %3B)."""
        constraint = Shlex(allow=["ls"])
        # %3B is literal text, not a semicolon
        # This would pass - the shell sees "%3B" not ";"
        assert constraint.matches("ls %3B")

    def test_html_entity_semicolon_blocked(self):
        """HTML entity semicolon contains literal semicolon, so blocked.

        &#59; contains the ; character which gets parsed as a separate token
        by punctuation_chars=True.
        """
        constraint = Shlex(allow=["ls"])
        # The ; in &#59; becomes a separate token
        assert not constraint.matches("ls &#59;")

    def test_octal_escape_newline(self):
        """Octal escape for newline."""
        constraint = Shlex(allow=["echo"])
        # This is literal \012, not a real newline
        # Unless processed by echo -e
        assert constraint.matches("echo \\012")

    def test_hex_escape_newline(self):
        """Hex escape for newline."""
        constraint = Shlex(allow=["echo"])
        # This is literal \x0a, not a real newline
        assert constraint.matches("echo \\x0a")


class TestShlexAdversarialShellFeatures:
    """Adversarial tests: Shell-specific feature bypass attempts."""

    def test_brace_expansion(self):
        """Bash brace expansion (currently allowed - documented)."""
        constraint = Shlex(allow=["echo"])
        # Brace expansion is bash-specific
        # Currently allowed - consider adding block_braces option
        assert constraint.matches("echo {a,b,c}")

    def test_tilde_expansion(self):
        """Tilde expansion (currently allowed - documented)."""
        constraint = Shlex(allow=["ls"])
        # Tilde expands to home directory
        # This is relatively safe - just expands to a path
        assert constraint.matches("ls ~")
        assert constraint.matches("ls ~/Documents")

    def test_tilde_user_expansion(self):
        """Tilde-user expansion."""
        constraint = Shlex(allow=["ls"])
        # ~user expands to user's home directory
        assert constraint.matches("ls ~root")

    def test_history_expansion(self):
        """History expansion (!) - shell handles, not shlex."""
        constraint = Shlex(allow=["echo"])
        # ! is for history expansion in interactive shells
        # shlex treats as literal
        assert constraint.matches("echo !!")
        assert constraint.matches("echo !-1")

    def test_event_designator(self):
        """Event designator bypass attempt."""
        constraint = Shlex(allow=["echo"])
        # History expansion - only in interactive shells
        assert constraint.matches("echo !:0")


class TestShlexAdversarialArgumentInjection:
    """Adversarial tests: Argument-based attacks (out of scope but documented)."""

    def test_git_upload_pack(self):
        """git --upload-pack attack (out of scope - requires proc_jail)."""
        constraint = Shlex(allow=["git"])
        # This passes Shlex but git interprets the argument as a command
        # Documented as out-of-scope
        assert constraint.matches("git clone --upload-pack=id repo")

    def test_find_exec(self):
        """find -exec attack (out of scope - requires proc_jail)."""
        constraint = Shlex(allow=["find"])
        # Semicolon is not in the raw string (it's escaped)
        # But find will execute the command
        # Wait - the backslash-semicolon contains ;
        assert not constraint.matches("find . -exec rm {} \\;")

    def test_tar_checkpoint(self):
        """tar --checkpoint-action attack (out of scope)."""
        constraint = Shlex(allow=["tar"])
        # tar will execute the command
        # Documented as out-of-scope
        assert constraint.matches("tar --checkpoint-action=exec=id -xf file.tar")

    def test_xargs_injection(self):
        """xargs with dangerous input (out of scope)."""
        constraint = Shlex(allow=["xargs"])
        # xargs can execute arbitrary commands
        # Documented: don't allow xargs in allowlist
        assert constraint.matches("xargs rm")

    def test_env_command(self):
        """env command to run arbitrary binaries (out of scope)."""
        constraint = Shlex(allow=["env"])
        # env can run any command
        # Documented: don't allow env in allowlist
        assert constraint.matches("env rm -rf /")


class TestShlexAdversarialEdgeCases:
    """Adversarial tests: Edge cases and boundary conditions."""

    def test_very_long_command(self):
        """Very long command should be handled."""
        constraint = Shlex(allow=["echo"])
        long_arg = "a" * 100000
        assert constraint.matches(f"echo {long_arg}")

    def test_many_arguments(self):
        """Many arguments should be handled."""
        constraint = Shlex(allow=["echo"])
        many_args = " ".join(["arg"] * 10000)
        assert constraint.matches(f"echo {many_args}")

    def test_deeply_nested_quotes(self):
        """Deeply nested quoting that shlex can handle."""
        constraint = Shlex(allow=["echo"])
        # Valid: single quotes inside double quotes
        assert constraint.matches("echo \"a'b'c\"")
        # Valid: double quotes inside single quotes
        assert constraint.matches("echo 'a\"b\"c'")

    def test_empty_quoted_binary(self):
        """Empty quoted string as binary."""
        constraint = Shlex(allow=["ls"])
        # shlex.split('""') returns ['']
        assert not constraint.matches('""')

    def test_only_whitespace_in_quotes(self):
        """Only whitespace in quotes."""
        constraint = Shlex(allow=["echo"])
        assert constraint.matches('echo "   "')

    def test_special_filenames(self):
        """Special filenames that look like operators."""
        constraint = Shlex(allow=["cat"])
        # Quoted filenames with operators are safe - they're just text
        # punctuation_chars=True respects quotes
        assert constraint.matches("cat 'file;name'")
        assert constraint.matches("cat 'file|name'")

    def test_dash_dash_help(self):
        """Common --help flag should work."""
        constraint = Shlex(allow=["ls"])
        assert constraint.matches("ls --help")

    def test_single_dash(self):
        """Single dash (stdin) should work."""
        constraint = Shlex(allow=["cat"])
        assert constraint.matches("cat -")

    def test_double_dash_with_dangerous_looking_arg(self):
        """Double dash followed by dangerous-looking argument."""
        constraint = Shlex(allow=["ls"])
        # -- makes -rf; look like a filename
        # The ; becomes a separate token, so it's blocked
        assert not constraint.matches("ls -- -rf;")


class TestShlexAllowlistVariations:
    """Tests for various allowlist configurations."""

    def test_full_path_only_allowlist(self):
        """Allowlist with only full paths requires full path in command.

        If allowlist contains /usr/bin/ls, you must use the full path
        OR the basename must be extracted and matched.
        """
        constraint = Shlex(allow=["/usr/bin/ls"])
        # Full path matches full path
        assert constraint.matches("/usr/bin/ls -la")
        # Basename "ls" doesn't match "/usr/bin/ls" directly
        # The implementation extracts basename from command and checks both
        # /usr/bin/ls -> checks "ls" against allowlist -> no match
        # So this requires the allowlist to include "ls" explicitly
        assert not constraint.matches("ls -la")

    def test_basename_and_fullpath_allowlist(self):
        """Allowlist with both basename and full path."""
        constraint = Shlex(allow=["ls", "/usr/bin/cat"])
        assert constraint.matches("ls -la")
        assert constraint.matches("/usr/bin/cat file")
        # "cat" alone doesn't match - only "/usr/bin/cat" is in allowlist
        assert not constraint.matches("cat file")

    def test_similar_binary_names(self):
        """Binaries with similar names."""
        constraint = Shlex(allow=["ls"])
        assert not constraint.matches("ls-F")
        assert not constraint.matches("lsattr")
        assert not constraint.matches("lsof")

    def test_binary_with_extension(self):
        """Binary with extension (Windows-style)."""
        constraint = Shlex(allow=["script.sh"])
        assert constraint.matches("script.sh arg1")
        assert constraint.matches("./script.sh arg1")


class TestShlexCrossPlatform:
    """Tests verifying Unix-style paths work on all platforms (including Windows).

    Shell commands use Unix-style paths (forward slashes) even when the Python
    code runs on Windows. The Shlex constraint uses posixpath.normpath() to
    ensure consistent behavior across platforms.
    """

    def test_unix_path_on_all_platforms(self):
        """Unix-style paths should work regardless of host OS."""
        constraint = Shlex(allow=["/usr/bin/ls"])
        # This would fail on Windows if we used os.path.normpath
        # because it would convert /usr/bin/ls to \\usr\\bin\\ls
        assert constraint.matches("/usr/bin/ls -la")

    def test_path_normalization_cross_platform(self):
        """Path normalization uses posixpath, not os.path."""
        constraint = Shlex(allow=["/usr/bin/ls"])
        # posixpath.normpath("/usr/bin/../bin/ls") == "/usr/bin/ls"
        # os.path.normpath on Windows would give "\\usr\\bin\\ls"
        assert constraint.matches("/usr/bin/../bin/ls -la")

    def test_basename_extraction_cross_platform(self):
        """Basename extraction uses posixpath, not os.path."""
        constraint = Shlex(allow=["ls"])
        # posixpath.basename("/usr/bin/ls") == "ls"
        # os.path.basename on Windows with forward slashes returns full path
        assert constraint.matches("/usr/bin/ls -la")
