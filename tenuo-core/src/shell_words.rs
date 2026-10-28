//! POSIX shell tokenization for [`crate::constraints::Shlex`].
//!
//! Words end at unquoted spaces, tabs, or operators. `#` is an ordinary word
//! character, never a comment, so an operator after `#` is still rejected even
//! when a shell would not treat `#` as a comment. A comma, bracket, or other
//! non-operator character stays inside the word, so `./ls,evil` is one
//! command name. Quoted and backslash-escaped operator characters are
//! literal arguments.
//!
//! [`check`] is the only decision. Callers that explain a denial use its
//! reason instead of a second parser.

use serde::Serialize;
use std::fmt;

/// Longest-match POSIX operators. A quoted or escaped character from this
/// set is an argument, not an operator.
const OPERATORS: &[&str] = &[
    "<<-", "&&", "||", ";;", "|&", "<<", ">>", "<&", ">&", "<>", "|", "&", ";", "<", ">", "(", ")",
];

const CONTROL_CHARS: &[char] = &[
    '\0', '\n', '\r', '\u{000b}', '\u{000c}', '\u{0007}', '\u{0008}', '\u{007f}',
];

/// A token from [`tokenize`]. `operator` is set only for an unquoted operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub operator: bool,
}

/// Why [`tokenize`] refused the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellError {
    /// A quote was still open at the end of the string.
    NoClosingQuotation,
    /// A backslash was the last character.
    NoEscapedCharacter,
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellError::NoClosingQuotation => write!(f, "unclosed quote"),
            ShellError::NoEscapedCharacter => write!(f, "trailing backslash"),
        }
    }
}

impl std::error::Error for ShellError {}

/// The core's decision for one command. `reason` is the explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShlexCheck {
    pub allowed: bool,
    pub reason: String,
    pub tokens: Vec<String>,
    pub operators: Vec<String>,
    pub expansion: Vec<String>,
    pub controls: Vec<String>,
    pub binary_allowed: bool,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
}

impl Lexer {
    fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        Some(ch)
    }

    fn starts_operator(&self) -> bool {
        self.match_operator().is_some()
    }

    /// Compare in place, skipping any `\\\n` line continuations inside an
    /// operator token (such as `>\\\n>` for `>>`). Copying the rest of the
    /// input here made the lexer quadratic in the command length.
    fn match_operator(&self) -> Option<(&'static str, usize)> {
        let rest = &self.chars[self.pos..];
        OPERATORS.iter().copied().find_map(|op| {
            let mut idx = 0;
            for ch in op.chars() {
                while idx + 1 < rest.len() && rest[idx] == '\\' && rest[idx + 1] == '\n' {
                    idx += 2;
                }
                if rest.get(idx) != Some(&ch) {
                    return None;
                }
                idx += 1;
            }
            Some((op, idx))
        })
    }

    fn skip_blank(&mut self) {
        loop {
            if matches!(self.peek(), Some(' ' | '\t')) {
                self.bump();
            } else if self.peek() == Some('\\') && self.chars.get(self.pos + 1) == Some(&'\n') {
                self.bump();
                self.bump();
            } else {
                break;
            }
        }
    }

    fn read_word(&mut self) -> Result<String, ShellError> {
        let mut text = String::new();
        let mut quote: Option<char> = None;
        loop {
            let Some(ch) = self.peek() else {
                if quote.is_some() {
                    return Err(ShellError::NoClosingQuotation);
                }
                return Ok(text);
            };
            match quote {
                None => match ch {
                    ' ' | '\t' | '\n' => return Ok(text),
                    '\\' => {
                        self.bump();
                        let Some(escaped) = self.bump() else {
                            return Err(ShellError::NoEscapedCharacter);
                        };
                        if escaped != '\n' {
                            text.push(escaped);
                        }
                    }
                    '\'' | '"' => {
                        self.bump();
                        quote = Some(ch);
                    }
                    _ if self.starts_operator() => return Ok(text),
                    _ => {
                        self.bump();
                        text.push(ch);
                    }
                },
                Some('\'') => {
                    self.bump();
                    if ch == '\'' {
                        quote = None;
                    } else {
                        text.push(ch);
                    }
                }
                Some('"') => {
                    if ch == '"' {
                        self.bump();
                        quote = None;
                    } else if ch == '\\' {
                        self.bump();
                        let Some(escaped) = self.bump() else {
                            return Err(ShellError::NoEscapedCharacter);
                        };
                        // POSIX: inside double quotes, backslash-newline is a
                        // line continuation (removed), and backslash is special
                        // only before $, `, ", and \.
                        if escaped == '\n' {
                            continue;
                        } else if matches!(escaped, '$' | '`' | '"' | '\\') {
                            text.push(escaped);
                        } else {
                            text.push('\\');
                            text.push(escaped);
                        }
                    } else {
                        self.bump();
                        text.push(ch);
                    }
                }
                Some(_) => unreachable!("quotes are only ' and \""),
            }
        }
    }

    fn next_token(&mut self) -> Result<Option<Token>, ShellError> {
        self.skip_blank();
        match self.peek() {
            None => Ok(None),
            Some('\n') => {
                let ch = self.bump().expect("peeked");
                Ok(Some(Token {
                    text: ch.to_string(),
                    operator: true,
                }))
            }
            Some(_) if self.starts_operator() => {
                let (op, consumed) = self.match_operator().expect("starts_operator");
                self.pos += consumed;
                Ok(Some(Token {
                    text: op.to_string(),
                    operator: true,
                }))
            }
            Some(_) => {
                let text = self.read_word()?;
                Ok(Some(Token {
                    text,
                    operator: false,
                }))
            }
        }
    }
}

/// Split `input` the way a POSIX shell splits words, without expansion.
pub fn tokenize(input: &str) -> Result<Vec<Token>, ShellError> {
    let mut lexer = Lexer::new(input);
    let mut tokens = Vec::new();
    while let Some(token) = lexer.next_token()? {
        tokens.push(token);
    }
    Ok(tokens)
}

fn binary_allowed(allow: &[String], binary: &str) -> bool {
    if binary.is_empty() || binary.contains("..") {
        return false;
    }
    // Each `allow` entry matches the command word literally. A bare entry such
    // as `ls` matches `ls` only, never `/usr/bin/ls`, `./ls`, or
    // `/tmp/attacker/ls`. Any command word containing `..` is rejected so
    // symlinks cannot combine with `..` to escape a pinned path.
    allow.iter().any(|entry| entry == binary)
}

fn denied(reason: impl Into<String>, extras: ShlexCheck) -> ShlexCheck {
    ShlexCheck {
        allowed: false,
        reason: reason.into(),
        ..extras
    }
}

/// Decide whether `command` is one allowlisted binary and literal arguments.
///
/// `$` and backticks are rejected anywhere in the raw string, including
/// inside single quotes, double quotes, and backslash escapes.
pub fn check(allow: &[String], command: &str) -> ShlexCheck {
    let blank = ShlexCheck {
        allowed: false,
        reason: String::new(),
        tokens: Vec::new(),
        operators: Vec::new(),
        expansion: Vec::new(),
        controls: Vec::new(),
        binary_allowed: false,
    };
    if command.is_empty() {
        return denied("empty command", blank);
    }
    let controls: Vec<String> = command
        .chars()
        .filter(|ch| CONTROL_CHARS.contains(ch))
        .map(|ch| ch.to_string())
        .collect();
    if !controls.is_empty() {
        return denied("control character", ShlexCheck { controls, ..blank });
    }
    let mut expansion = Vec::new();
    if command.contains('$') {
        expansion.push("$".to_string());
    }
    if command.contains('`') {
        expansion.push("`".to_string());
    }
    if !expansion.is_empty() {
        return denied("shell expansion", ShlexCheck { expansion, ..blank });
    }
    let tokens = match tokenize(command) {
        Ok(tokens) => tokens,
        Err(err) => return denied(err.to_string(), blank),
    };
    if tokens.is_empty() {
        return denied("empty command", blank);
    }
    let operators: Vec<String> = tokens
        .iter()
        .filter(|token| token.operator)
        .map(|token| token.text.clone())
        .collect();
    let words: Vec<String> = tokens.into_iter().map(|token| token.text).collect();
    let binary_allowed = binary_allowed(allow, &words[0]);
    if !binary_allowed {
        return denied(
            format!("binary '{}' is not allowlisted", words[0]),
            ShlexCheck {
                tokens: words,
                operators,
                binary_allowed: false,
                ..blank
            },
        );
    }
    if let Some(op) = operators.first() {
        return denied(
            format!("operator '{op}'"),
            ShlexCheck {
                tokens: words,
                operators,
                binary_allowed: true,
                ..blank
            },
        );
    }
    ShlexCheck {
        allowed: true,
        reason: "allowed".to_string(),
        tokens: words,
        operators,
        expansion,
        controls,
        binary_allowed: true,
    }
}

/// Whether [`check`] allows the command.
pub fn command_allowed(allow: &[String], command: &str) -> bool {
    check(allow, command).allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(input: &str) -> Vec<String> {
        tokenize(input)
            .unwrap_or_else(|err| panic!("{err} for {input:?}"))
            .into_iter()
            .map(|token| token.text)
            .collect()
    }

    #[test]
    fn words_follow_the_shell_not_cpython_shlex() {
        let cases = [
            ("ls -la /tmp", vec!["ls", "-la", "/tmp"]),
            ("ls \"foo; bar\"", vec!["ls", "foo; bar"]),
            ("ls 'foo && bar'", vec!["ls", "foo && bar"]),
            ("ls -la; rm -rf /", vec!["ls", "-la", ";", "rm", "-rf", "/"]),
            ("ls;rm", vec!["ls", ";", "rm"]),
            ("ls&&rm", vec!["ls", "&&", "rm"]),
            ("echo \"AT&T\"", vec!["echo", "AT&T"]),
            ("echo AT&T", vec!["echo", "AT", "&", "T"]),
            ("cat <<EOF", vec!["cat", "<<", "EOF"]),
            ("ls\t-la", vec!["ls", "-la"]),
            ("\"ls\" -la", vec!["ls", "-la"]),
            ("ls -la \"\"", vec!["ls", "-la", ""]),
            ("ls foo\\ bar", vec!["ls", "foo bar"]),
            ("echo {a,b,c}", vec!["echo", "{a,b,c}"]),
            ("ls file[12].txt", vec!["ls", "file[12].txt"]),
            ("echo hello!", vec!["echo", "hello!"]),
            ("echo hello #world", vec!["echo", "hello", "#world"]),
            ("foo#bar", vec!["foo#bar"]),
            ("ls foo#; rm", vec!["ls", "foo#", ";", "rm"]),
            ("./ls,evil -la", vec!["./ls,evil", "-la"]),
            (
                "find . -exec rm {} \\;",
                vec!["find", ".", "-exec", "rm", "{}", ";"],
            ),
            ("echo \";\"", vec!["echo", ";"]),
            ("ls #; rm", vec!["ls", "#", ";", "rm"]),
            ("echo 'a'\"b\"'c'", vec!["echo", "abc"]),
            ("echo \"a\\\"b;c\"", vec!["echo", "a\"b;c"]),
            ("echo \"a\\\\b\"", vec!["echo", "a\\b"]),
            ("echo \"a\\b\"", vec!["echo", "a\\b"]),
            ("echo \"a\\\"\"; rm", vec!["echo", "a\"", ";", "rm"]),
            ("echo \"a\\\\\"; rm", vec!["echo", "a\\", ";", "rm"]),
            ("echo foo\\\nbar", vec!["echo", "foobar"]),
            ("echo \"foo\\\nbar\"", vec!["echo", "foobar"]),
            ("echo 'foo\\\nbar'", vec!["echo", "foo\\\nbar"]),
            ("echo \\\n bar", vec!["echo", "bar"]),
            ("echo foo\\\n bar", vec!["echo", "foo", "bar"]),
            ("cat >\\\n> file", vec!["cat", ">>", "file"]),
            ("ls &\\\n& rm", vec!["ls", "&&", "rm"]),
            ("echo a\rb", vec!["echo", "a\rb"]),
            ("echo \\\n", vec!["echo"]),
            ("\\\n", Vec::<&str>::new()),
            ("café --help", vec!["café", "--help"]),
        ];
        for (input, expected) in cases {
            assert_eq!(words(input), expected, "{input:?}");
        }
    }

    #[test]
    fn hash_inside_a_word_does_not_hide_an_operator() {
        let allow = vec!["ls".to_string()];
        let decision = check(&allow, "ls foo#; rm -rf /");
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "operator ';'");
        assert!(decision.binary_allowed);
    }

    #[test]
    fn comma_stays_in_the_command_name() {
        let allow = vec!["ls".to_string()];
        let decision = check(&allow, "./ls,evil -la");
        assert!(!decision.allowed);
        assert_eq!(decision.tokens, vec!["./ls,evil", "-la"]);
        assert!(!decision.binary_allowed);
    }

    #[test]
    fn escaped_and_quoted_operators_are_arguments() {
        let allow = vec!["echo".to_string(), "find".to_string()];
        assert!(command_allowed(&allow, "echo \";\""));
        assert!(command_allowed(&allow, "find . -exec rm {} \\;"));
        assert!(!command_allowed(&allow, "echo ;"));
    }

    #[test]
    fn hash_never_hides_an_operator() {
        let allow = vec!["ls".to_string()];
        assert!(!command_allowed(&allow, "ls #; rm -rf /"));
        assert!(!command_allowed(&allow, "ls # ; rm -rf /"));
        assert!(!command_allowed(&allow, "ls # |& sh"));
        assert!(command_allowed(&allow, "ls -la # list everything"));
    }

    #[test]
    fn tokenize_rejects_unbalanced_quotes_and_trailing_escape() {
        assert_eq!(tokenize("ls \""), Err(ShellError::NoClosingQuotation));
        assert_eq!(tokenize("ls '"), Err(ShellError::NoClosingQuotation));
        assert_eq!(tokenize("ls \\"), Err(ShellError::NoEscapedCharacter));
    }

    #[test]
    fn binary_allowlist_requires_exact_command_word_and_rejects_dotdot() {
        let bare = vec!["ls".to_string()];
        assert!(command_allowed(&bare, "ls -la"));
        assert!(!command_allowed(&bare, "/usr/bin/ls -la"));
        assert!(!command_allowed(&bare, "/tmp/attacker/ls -la"));
        assert!(!command_allowed(&bare, "./ls -la"));
        assert!(!command_allowed(&bare, "../ls -la"));

        let pinned = vec!["/usr/bin/ls".to_string()];
        assert!(command_allowed(&pinned, "/usr/bin/ls -la"));
        assert!(!command_allowed(&pinned, "ls -la"));
        assert!(!command_allowed(&pinned, "/usr/bin/../bin/ls -la"));
        assert!(!command_allowed(&pinned, "/tmp/l/../../usr/bin/ls -la"));
    }

    #[test]
    fn operators_inside_quotes_are_literals() {
        let allow = vec!["ls".to_string(), "echo".to_string(), "grep".to_string()];
        assert!(command_allowed(&allow, "ls \"foo; bar\""));
        assert!(command_allowed(&allow, "ls 'foo && bar'"));
        assert!(command_allowed(&allow, "grep \"a|b\" file"));
        assert!(command_allowed(&allow, "echo \"AT&T\""));
        assert!(command_allowed(&allow, "echo \"<html>\""));
        assert!(command_allowed(&allow, "echo \"a\\\"b;c\""));
        assert!(command_allowed(&allow, "echo \"a\\\\b\""));
        assert!(command_allowed(&allow, "echo \"a\\b\""));
        assert!(!command_allowed(&allow, "echo \"a\\\"\"; rm"));
        assert!(!command_allowed(&allow, "echo \"a\\\\\"; rm"));
        assert!(!command_allowed(&allow, "echo foo\\\nbar"));
    }

    #[test]
    fn expansion_is_rejected_inside_quotes() {
        let allow = vec!["echo".to_string()];
        assert!(!command_allowed(&allow, "echo \"$VAR\""));
        assert!(!command_allowed(&allow, "echo '$HOME'"));
        assert!(!command_allowed(&allow, "echo \"\\$HOME\""));
        assert!(!command_allowed(&allow, "echo `id`"));
    }

    #[test]
    fn unquoted_operator_runs_are_rejected() {
        let allow = vec!["cat".to_string(), "ls".to_string()];
        assert!(!command_allowed(&allow, "cat <> /etc/passwd"));
        assert!(!command_allowed(&allow, "ls;rm"));
        assert!(!command_allowed(&allow, "ls&&rm"));
        assert!(!command_allowed(&allow, "cat <<EOF"));
    }

    #[test]
    fn long_commands_tokenize_in_linear_time() {
        // One long word, then one long run of quoted operator characters.
        // The quadratic lexer took about 4 s for 100 KB in a release build;
        // these inputs take milliseconds now, with room for instrumented CI runs.
        let allow = vec!["ls".to_string()];
        let word = format!("ls {}", "a".repeat(200_000));
        let quoted = format!("ls \"{}\"", ";".repeat(200_000));
        let start = std::time::Instant::now();
        assert!(command_allowed(&allow, &word));
        assert!(command_allowed(&allow, &quoted));
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "400 KB of input took {elapsed:?}"
        );
    }

    /// Shells to compare against: `/bin/sh` plus dash and bash when present.
    /// CI's `/bin/sh` is dash and macOS's is bash, so each host checks both
    /// when it can.
    #[cfg(unix)]
    fn oracle_shells() -> Vec<std::path::PathBuf> {
        let mut shells: Vec<std::path::PathBuf> = Vec::new();
        for candidate in [
            "/bin/sh",
            "/bin/dash",
            "/usr/bin/dash",
            "/bin/bash",
            "/usr/bin/bash",
        ] {
            let Ok(real) = std::fs::canonicalize(candidate) else {
                continue;
            };
            if !shells
                .iter()
                .any(|seen| std::fs::canonicalize(seen).ok().as_ref() == Some(&real))
            {
                shells.push(candidate.into());
            }
        }
        assert!(!shells.is_empty(), "no POSIX shell found");
        shells
    }

    /// Run `command` under `shell` with a recording stub on `PATH`.
    /// Each invocation is `[argv0, arg, ...]`. `set -f` keeps globs literal
    /// so the comparison is about word splitting, not filename generation.
    #[cfg(unix)]
    fn shell_invocations(shell: &std::path::Path, command: &str) -> Vec<Vec<String>> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenuo-shlex-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let stub = dir.join("stub");
        std::fs::write(
            &stub,
            "#!/bin/sh\nprintf '%s\\0' \"$0\" >> \"$TENUO_SHLEX_LOG\"\nfor arg in \"$@\"; do printf '%s\\0' \"$arg\" >> \"$TENUO_SHLEX_LOG\"; done\nprintf '\\n' >> \"$TENUO_SHLEX_LOG\"\n",
        )
        .expect("stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&stub).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&stub, perms).unwrap();
        }
        for name in ["ls", "rm", "echo", "cat", "grep", "find", "npm", "ls,evil"] {
            let path = dir.join(name);
            let _ = std::fs::remove_file(&path);
            std::os::unix::fs::symlink(&stub, &path).expect("symlink");
        }
        let log = dir.join("log");
        let output = std::process::Command::new(shell)
            .arg("-c")
            // `set -f` stops pathname expansion. Brace expansion is a bash
            // extra; POSIX words keep `{a,b,c}` together. Turn it off only
            // when `$-` shows it: `set +o braceexpand` is an error in dash,
            // and a special builtin error exits a non-interactive shell even
            // with `|| true`.
            .arg("set -f; case $- in *B*) set +B;; esac; eval \"$1\"")
            .arg("sh")
            .arg(command)
            .current_dir(&dir)
            .env("PATH", &dir)
            .env("TENUO_SHLEX_LOG", &log)
            .output()
            .expect("sh");
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            output.status.success() || !text.is_empty(),
            "{} exited {:?} without invocations: {}",
            shell.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                line.split('\0')
                    .filter(|field| !field.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn accepted_commands_match_one_shell_invocation() {
        // `echo` is a shell builtin, so the recording stub would never run.
        // These commands use external names that the stub provides.
        let samples = [
            "ls -la /tmp",
            "ls \"foo; bar\"",
            "ls 'foo && bar'",
            "ls \";\"",
            "ls {a,b,c}",
            "ls foo\\ bar",
            "ls foo#bar",
            "ls \"#world\"",
            "ls \"a\\\"b;c\"",
            "ls \"a\\\\b\"",
            "ls \"a\\b\"",
            "find . -exec rm {} \\;",
            "ls 'a'\"b\"'c'",
        ];
        for shell in oracle_shells() {
            let sh = shell.display();
            for command in samples {
                let decision = check(&["ls".into(), "find".into()], command);
                assert!(decision.allowed, "{command}: {}", decision.reason);
                let calls = shell_invocations(&shell, command);
                assert_eq!(calls.len(), 1, "{sh}: {command} invoked {calls:?}");
                let invoked = calls[0][0].rsplit('/').next().unwrap_or(&calls[0][0]);
                let expected_name = decision.tokens[0]
                    .rsplit('/')
                    .next()
                    .unwrap_or(&decision.tokens[0]);
                assert_eq!(invoked, expected_name, "{sh}: {command}");
                assert_eq!(calls[0][1..], decision.tokens[1..], "{sh}: {command}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn shell_runs_the_command_hidden_by_a_midword_hash() {
        let command = "ls foo#; rm -rf /";
        assert!(!command_allowed(&["ls".into()], command));
        for shell in oracle_shells() {
            let calls = shell_invocations(&shell, command);
            assert!(
                calls.iter().any(|call| call[0].ends_with("rm")),
                "{} should run rm, got {calls:?}",
                shell.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn shell_runs_the_comma_command_not_ls() {
        let command = "./ls,evil -la";
        assert!(!command_allowed(&["ls".into()], command));
        for shell in oracle_shells() {
            let calls = shell_invocations(&shell, command);
            assert_eq!(calls.len(), 1, "{}: {calls:?}", shell.display());
            assert!(calls[0][0].ends_with("ls,evil"), "{calls:?}");
            assert_eq!(calls[0][1..], ["-la"]);
        }
    }
}
