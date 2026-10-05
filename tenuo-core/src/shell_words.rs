//! POSIX shell tokenization for [`crate::constraints::Shlex`].
//!
//! One tokenizer for every SDK. The state machine follows CPython
//! `shlex.shlex(posix=True, punctuation_chars=True)`: single and double
//! quotes, backslash escapes, and runs of `();<>|&` as operator tokens.
//! `#` comments through the end of the line.
//!
//! [`command_allowed`] is the security decision. It rejects control
//! characters and `$` / backticks in the raw string, including inside
//! quotes, then rejects unquoted operator tokens.

use std::fmt;

/// Punctuation that `shlex` with `punctuation_chars=True` splits into operator tokens.
const PUNCTUATION: &str = "();<>|&";

/// Characters CPython adds to `wordchars` in POSIX mode with punctuation enabled.
/// Latin-1 letters skip U+00D7 and U+00F7, matching `Lib/shlex.py`.
const WORD_EXTRA: &str = "ßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ\
ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞ~-./*?=";

/// Operator spellings the Python evaluator rejected by exact token match.
/// Unquoted runs of [`PUNCTUATION`] are rejected even when the spelling is
/// not in this list (`<>`, `<&`).
const DANGEROUS_TOKENS: &[&str] = &[
    "|", "||", "&", "&&", ";", ">", ">>", "<", "<<", "<<<", "(", ")",
];

const CONTROL_CHARS: &[char] = &[
    '\0', '\n', '\r', '\u{000b}', '\u{000c}', '\u{0007}', '\u{0008}', '\u{007f}',
];

/// A token from [`tokenize`]. `operator` is set for an unquoted run of [`PUNCTUATION`].
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
            ShellError::NoClosingQuotation => write!(f, "No closing quotation"),
            ShellError::NoEscapedCharacter => write!(f, "No escaped character"),
        }
    }
}

impl std::error::Error for ShellError {}

#[derive(Clone, Copy)]
enum State {
    Whitespace,
    Word,
    Punct,
    Quote(char),
    Escape,
    Done,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    pushback: Vec<char>,
    state: State,
    escape_back: State,
}

impl Lexer {
    fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            pushback: Vec::new(),
            state: State::Whitespace,
            escape_back: State::Word,
        }
    }

    fn next_char(&mut self) -> Option<char> {
        if let Some(ch) = self.pushback.pop() {
            return Some(ch);
        }
        let ch = self.chars.get(self.pos).copied()?;
        self.pos += 1;
        Some(ch)
    }

    fn push_char(&mut self, ch: char) {
        self.pushback.push(ch);
    }

    /// Consume through the next newline, which `shlex` does for `#` comments.
    fn skip_comment_line(&mut self) {
        loop {
            match self.next_char() {
                None | Some('\n') => break,
                Some(_) => {}
            }
        }
    }

    fn read_token(&mut self) -> Result<Option<Token>, ShellError> {
        if matches!(self.state, State::Done) {
            return Ok(None);
        }

        let mut text = String::new();
        let mut quoted = false;
        let mut operator = false;

        loop {
            let next = self.next_char();
            match self.state {
                State::Done => return Ok(None),
                State::Whitespace => match next {
                    None => {
                        self.state = State::Done;
                        return Ok(None);
                    }
                    Some(ch) if is_whitespace(ch) => {}
                    Some('#') => self.skip_comment_line(),
                    Some('\\') => {
                        self.escape_back = State::Word;
                        self.state = State::Escape;
                    }
                    Some(ch) if is_word_char(ch) => {
                        text.push(ch);
                        self.state = State::Word;
                    }
                    Some(ch) if is_punctuation(ch) => {
                        text.push(ch);
                        operator = true;
                        self.state = State::Punct;
                    }
                    Some(ch @ ('\'' | '"')) => {
                        // POSIX mode does not keep the opening quote.
                        self.state = State::Quote(ch);
                    }
                    Some(ch) => {
                        text.push(ch);
                        self.state = State::Whitespace;
                        return Ok(Some(Token {
                            text,
                            operator: false,
                        }));
                    }
                },
                State::Quote(quote) => {
                    quoted = true;
                    match next {
                        None => return Err(ShellError::NoClosingQuotation),
                        Some(ch) if ch == quote => self.state = State::Word,
                        Some('\\') if quote == '"' => {
                            self.escape_back = State::Quote(quote);
                            self.state = State::Escape;
                        }
                        Some(ch) => text.push(ch),
                    }
                }
                State::Escape => {
                    let Some(ch) = next else {
                        return Err(ShellError::NoEscapedCharacter);
                    };
                    if let State::Quote(quote) = self.escape_back {
                        // Inside double quotes, only the quote and the backslash
                        // itself consume the escape. Anything else keeps the slash.
                        if ch != '\\' && ch != quote {
                            text.push('\\');
                        }
                    }
                    text.push(ch);
                    self.state = self.escape_back;
                }
                State::Word | State::Punct => {
                    let is_punct_state = matches!(self.state, State::Punct);
                    match next {
                        None => {
                            self.state = State::Done;
                            if text.is_empty() && !quoted {
                                return Ok(None);
                            }
                            return Ok(Some(Token { text, operator }));
                        }
                        Some(ch) if is_whitespace(ch) => {
                            self.state = State::Whitespace;
                            if text.is_empty() && !quoted {
                                continue;
                            }
                            return Ok(Some(Token { text, operator }));
                        }
                        Some('#') => {
                            self.skip_comment_line();
                            self.state = State::Whitespace;
                            if text.is_empty() && !quoted {
                                continue;
                            }
                            return Ok(Some(Token { text, operator }));
                        }
                        Some(ch) if is_punct_state && is_punctuation(ch) => {
                            text.push(ch);
                        }
                        Some(ch) if is_punct_state => {
                            if !is_whitespace(ch) {
                                self.push_char(ch);
                            }
                            self.state = State::Whitespace;
                            return Ok(Some(Token {
                                text,
                                operator: true,
                            }));
                        }
                        Some(ch @ ('\'' | '"')) => {
                            self.state = State::Quote(ch);
                        }
                        Some('\\') => {
                            self.escape_back = State::Word;
                            self.state = State::Escape;
                        }
                        Some(ch) if is_word_char(ch) => text.push(ch),
                        Some(ch) => {
                            self.push_char(ch);
                            self.state = State::Whitespace;
                            if text.is_empty() && !quoted {
                                continue;
                            }
                            return Ok(Some(Token { text, operator }));
                        }
                    }
                }
            }
        }
    }
}

fn is_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n')
}

fn is_punctuation(ch: char) -> bool {
    PUNCTUATION.contains(ch)
}

fn is_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || WORD_EXTRA.contains(ch)
}

/// Split `input` the way CPython `shlex.shlex(posix=True, punctuation_chars=True)` does.
pub fn tokenize(input: &str) -> Result<Vec<Token>, ShellError> {
    let mut lexer = Lexer::new(input);
    let mut tokens = Vec::new();
    while let Some(token) = lexer.read_token()? {
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
    allow
        .iter()
        .any(|entry| entry == &normalized || entry == base)
}

/// Whether `command` is a single allowlisted binary with no shell operators.
///
/// `$` and backticks are rejected anywhere in the raw string, including
/// inside single quotes, double quotes, and backslash escapes. A double-quoted
/// `$` still expands in a POSIX shell; the raw scan also refuses the
/// single-quoted and escaped forms rather than widening the warrant.
pub fn command_allowed(allow: &[String], command: &str) -> bool {
    if command.is_empty() {
        return false;
    }
    if command.chars().any(|ch| CONTROL_CHARS.contains(&ch)) {
        return false;
    }
    if command.contains('$') || command.contains('`') {
        return false;
    }
    let tokens = match tokenize(command) {
        Ok(tokens) => tokens,
        Err(_) => return false,
    };
    if tokens.is_empty() {
        return false;
    }
    if !binary_allowed(allow, &tokens[0].text) {
        return false;
    }
    for token in &tokens {
        if token.operator || DANGEROUS_TOKENS.contains(&token.text.as_str()) {
            return false;
        }
    }
    true
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
    fn tokenize_matches_cpython_shlex() {
        let cases = [
            ("ls -la /tmp", vec!["ls", "-la", "/tmp"]),
            ("ls \"foo; bar\"", vec!["ls", "foo; bar"]),
            ("ls 'foo && bar'", vec!["ls", "foo && bar"]),
            ("ls -la; rm -rf /", vec!["ls", "-la", ";", "rm", "-rf", "/"]),
            ("ls;rm", vec!["ls", ";", "rm"]),
            ("ls&&rm", vec!["ls", "&&", "rm"]),
            ("ls||rm", vec!["ls", "||", "rm"]),
            ("echo \"AT&T\"", vec!["echo", "AT&T"]),
            ("echo AT&T", vec!["echo", "AT", "&", "T"]),
            ("cat <<EOF", vec!["cat", "<<", "EOF"]),
            ("cat <<<'hello'", vec!["cat", "<<<", "hello"]),
            (
                "diff <(ls) <(ls -la)",
                vec!["diff", "<(", "ls", ")", "<(", "ls", "-la", ")"],
            ),
            ("ls\t-la", vec!["ls", "-la"]),
            ("\"ls\" -la", vec!["ls", "-la"]),
            ("ls -la \"\"", vec!["ls", "-la", ""]),
            ("\"\"", vec![""]),
            ("ls foo\\ bar", vec!["ls", "foo bar"]),
            (
                "echo {a,b,c}",
                vec!["echo", "{", "a", ",", "b", ",", "c", "}"],
            ),
            ("ls *", vec!["ls", "*"]),
            ("ls file?.txt", vec!["ls", "file?.txt"]),
            (
                "ls file[12].txt",
                vec!["ls", "file", "[", "12", "]", ".txt"],
            ),
            ("ls &#59;", vec!["ls", "&"]),
            ("echo hello #world", vec!["echo", "hello"]),
            ("echo hello!", vec!["echo", "hello", "!"]),
            (
                "find . -exec rm {} \\;",
                vec!["find", ".", "-exec", "rm", "{", "}", ";"],
            ),
            ("ls foo;bar", vec!["ls", "foo", ";", "bar"]),
            ("cat <> /etc/passwd", vec!["cat", "<>", "/etc/passwd"]),
            ("/usr/bin/../bin/ls -la", vec!["/usr/bin/../bin/ls", "-la"]),
            ("\"my program\" arg1", vec!["my program", "arg1"]),
            ("echo 'hello \"world\"'", vec!["echo", "hello \"world\""]),
            ("echo 'a'\"b\"'c'", vec!["echo", "abc"]),
            ("ls #; rm", vec!["ls"]),
            ("foo#bar", vec!["foo"]),
            ("echo \"$(date)\"", vec!["echo", "$(date)"]),
            ("echo '$HOME'", vec!["echo", "$HOME"]),
            ("ls ~/Documents", vec!["ls", "~/Documents"]),
            ("npm   install   express", vec!["npm", "install", "express"]),
            ("café --help", vec!["café", "--help"]),
            ("ls -- -rf;", vec!["ls", "--", "-rf", ";"]),
            (
                "git clone --upload-pack=id repo",
                vec!["git", "clone", "--upload-pack=id", "repo"],
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(words(input), expected, "{input:?}");
        }
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
}
