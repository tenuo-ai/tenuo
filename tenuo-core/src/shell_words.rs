//! POSIX shell tokenization for [`crate::constraints::Shlex`].
//!
//! Words end at unquoted spaces, tabs, or operators. `#` starts a comment
//! only when it is the first character of a word. A comma, bracket, or other
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

    fn rest(&self) -> String {
        self.chars[self.pos..].iter().collect()
    }

    fn starts_operator(&self) -> bool {
        self.match_operator().is_some()
    }

    fn match_operator(&self) -> Option<&'static str> {
        let rest = self.rest();
        OPERATORS.iter().copied().find(|op| rest.starts_with(op))
    }

    fn skip_blank(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
    }

    /// `#` comments only at the start of a word. The `#` and the rest of the
    /// line are discarded. A `#` later in a word is an ordinary character.
    fn skip_comment(&mut self) {
        if self.peek() != Some('#') {
            return;
        }
        while let Some(ch) = self.bump() {
            if ch == '\n' {
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
                    ' ' | '\t' | '\n' | '\r' => return Ok(text),
                    '\\' => {
                        self.bump();
                        let Some(escaped) = self.bump() else {
                            return Err(ShellError::NoEscapedCharacter);
                        };
                        text.push(escaped);
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
                        // POSIX: inside double quotes, backslash is special
                        // only before $, `, ", \, and newline.
                        if matches!(escaped, '$' | '`' | '"' | '\\' | '\n') {
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
        loop {
            self.skip_blank();
            match self.peek() {
                None => return Ok(None),
                Some('#') => self.skip_comment(),
                Some('\n' | '\r') => {
                    let ch = self.bump().expect("peeked");
                    return Ok(Some(Token {
                        text: ch.to_string(),
                        operator: true,
                    }));
                }
                Some(_) if self.starts_operator() => {
                    let op = self.match_operator().expect("starts_operator");
                    for _ in op.chars() {
                        self.bump();
                    }
                    return Ok(Some(Token {
                        text: op.to_string(),
                        operator: true,
                    }));
                }
                Some(_) => {
                    let text = self.read_word()?;
                    return Ok(Some(Token {
                        text,
                        operator: false,
                    }));
                }
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

/// POSIX `normpath`. Two leading slashes are preserved; three or more collapse.
pub fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let mut initial_slashes: usize = 0;
    if path.starts_with('/') {
        initial_slashes = if path.starts_with("//") && !path.starts_with("///") {
            2
        } else {
            1
        };
    }
    let mut comps = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".."
            || (initial_slashes == 0 && comps.is_empty())
            || comps.last().map(String::as_str) == Some("..")
        {
            comps.push(comp.to_string());
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let mut out = comps.join("/");
    if initial_slashes > 0 {
        out.insert_str(0, &"/".repeat(initial_slashes));
    }
    if out.is_empty() {
        ".".to_string()
    } else {
        out
    }
}

fn binary_allowed(allow: &[String], binary: &str) -> bool {
    let normalized = if binary.contains('/') {
        posix_normpath(binary)
    } else {
        binary.to_string()
    };
    let base = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    // A bare allow entry matches that word and the final component of a path.
    // `allow=["ls"]` admits `/tmp/attacker/ls`. It does not admit `./ls,evil`.
    allow
        .iter()
        .any(|entry| entry == &normalized || entry == base)
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
            ("echo hello #world", vec!["echo", "hello"]),
            ("foo#bar", vec!["foo#bar"]),
            ("ls foo#; rm", vec!["ls", "foo#", ";", "rm"]),
            ("./ls,evil -la", vec!["./ls,evil", "-la"]),
            (
                "find . -exec rm {} \\;",
                vec!["find", ".", "-exec", "rm", "{}", ";"],
            ),
            ("echo \";\"", vec!["echo", ";"]),
            ("ls #; rm", vec!["ls"]),
            ("echo 'a'\"b\"'c'", vec!["echo", "abc"]),
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
    fn comment_at_the_start_of_a_word_is_a_comment() {
        let allow = vec!["ls".to_string()];
        assert!(command_allowed(&allow, "ls #; rm -rf /"));
    }

    #[test]
    fn tokenize_rejects_unbalanced_quotes_and_trailing_escape() {
        assert_eq!(tokenize("ls \""), Err(ShellError::NoClosingQuotation));
        assert_eq!(tokenize("ls '"), Err(ShellError::NoClosingQuotation));
        assert_eq!(tokenize("ls \\"), Err(ShellError::NoEscapedCharacter));
    }

    #[test]
    fn posix_normpath_matches_python() {
        assert_eq!(posix_normpath("/usr/bin/../bin/ls"), "/usr/bin/ls");
        assert_eq!(posix_normpath("//bin//ls"), "//bin/ls");
        assert_eq!(posix_normpath("/bin/./ls"), "/bin/ls");
        assert_eq!(posix_normpath("./ls"), "ls");
        assert_eq!(posix_normpath("../../../usr/bin/ls"), "../../../usr/bin/ls");
    }

    #[test]
    fn operators_inside_quotes_are_literals() {
        let allow = vec!["ls".to_string(), "echo".to_string(), "grep".to_string()];
        assert!(command_allowed(&allow, "ls \"foo; bar\""));
        assert!(command_allowed(&allow, "ls 'foo && bar'"));
        assert!(command_allowed(&allow, "grep \"a|b\" file"));
        assert!(command_allowed(&allow, "echo \"AT&T\""));
        assert!(command_allowed(&allow, "echo \"<html>\""));
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

    /// Run `command` under `/bin/sh` with a recording stub on `PATH`.
    /// Each invocation is `[argv0, arg, ...]`. `set -f` keeps globs literal
    /// so the comparison is about word splitting, not filename generation.
    #[cfg(unix)]
    fn shell_invocations(command: &str) -> Vec<Vec<String>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tenuo-shlex-{nanos}"));
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
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            // `set -f` stops pathname expansion. `braceexpand` is a bash
            // extra; POSIX words keep `{a,b,c}` together. Turn it off when
            // the shell has it so the comparison is word splitting.
            .arg("set -f; set +o braceexpand 2>/dev/null || true; eval \"$1\"")
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
            "sh failed without invocations: {}",
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
            "ls #; rm -rf /",
            "ls hello #world",
            "find . -exec rm {} \\;",
            "ls 'a'\"b\"'c'",
        ];
        for command in samples {
            let decision = check(&["ls".into(), "find".into()], command);
            assert!(decision.allowed, "{command}: {}", decision.reason);
            let calls = shell_invocations(command);
            assert_eq!(calls.len(), 1, "{command} invoked {calls:?}");
            let invoked = calls[0][0].rsplit('/').next().unwrap_or(&calls[0][0]);
            let expected_name = decision.tokens[0]
                .rsplit('/')
                .next()
                .unwrap_or(&decision.tokens[0]);
            assert_eq!(invoked, expected_name, "{command}");
            assert_eq!(calls[0][1..], decision.tokens[1..], "{command}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn shell_runs_the_command_hidden_by_a_midword_hash() {
        let command = "ls foo#; rm -rf /";
        assert!(!command_allowed(&["ls".into()], command));
        let calls = shell_invocations(command);
        assert!(
            calls.iter().any(|call| call[0].ends_with("rm")),
            "shell should run rm, got {calls:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shell_runs_the_comma_command_not_ls() {
        let command = "./ls,evil -la";
        assert!(!command_allowed(&["ls".into()], command));
        let calls = shell_invocations(command);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0][0].ends_with("ls,evil"), "{calls:?}");
        assert_eq!(calls[0][1..], ["-la"]);
    }
}
