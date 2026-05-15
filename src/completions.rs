use crate::{
    Error, Result,
    cli::{Commands, ShellKind},
    out,
};
use indoc::indoc;
use std::{env, fs, path::PathBuf, process::Command};
use tracing::debug;

type Subcommands = Vec<(&'static str, fn() -> CompletionNode)>;

type ValuesFn = fn(&str, &[String]) -> Vec<String>;

/// A node in the completion tree, describing what can be typed at a given position.
pub struct CompletionNode {
    /// Sub-command names available at this level.
    pub commands: Vec<&'static str>,
    /// `--long` flag names available at this level.
    pub args: Vec<&'static str>,
    /// Mapping of sub-command name → a function that builds the next `CompletionNode`.
    pub subcommands: Subcommands,
    /// Dynamic completions for positional arguments at this node.
    /// Called with the current prefix and the preceding words on the command line.
    /// The words slice lets the function inspect flag values already typed (e.g. `--realm`).
    /// Return at most [`COMPLETION_PAGE_SIZE`] candidates.
    /// If exactly that many are returned, the caller signals "keep typing to narrow".
    pub values: Option<ValuesFn>,
}

/// Maximum number of items a [`CompletionNode::values`] function should return.
/// Returning exactly this many signals that the result set was truncated.
pub const COMPLETION_PAGE_SIZE: u64 = 10;

pub fn bash_completions_script() -> &'static str {
    indoc! {r#"
        _kcm_completions() {
            local cur="${COMP_WORDS[$COMP_CWORD]}"
            local words=("${COMP_WORDS[@]:1:$COMP_CWORD-1}")
            local IFS=$'\n'
            local output
            output=$(kcm completions complete "--cur=$cur" -- "${words[@]}" 2>/dev/null)
            COMPREPLY=($(grep -v '^#' <<< "$output" | compgen -W "$(cat)" -- "$cur"))
        }
        complete -o default -F _kcm_completions kcm
    "#}
}

fn find_zsh_completions_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or(Error::InvalidConfigDir)?;

    // Query zsh for its fpath and pick the first user-writable directory under $HOME
    if let Ok(output) = Command::new("zsh").args(["-ic", "echo $fpath"]).output() {
        let fpath_str = String::from_utf8_lossy(&output.stdout);
        for dir in fpath_str.split_whitespace() {
            let p = PathBuf::from(dir);
            if p.starts_with(&home) {
                debug!(path = %p.display(), "found user fpath directory");
                fs::create_dir_all(&p)?;
                return Ok(p);
            }
        }
    }

    // Fallback to ~/.zfunc
    let fallback = home.join(".zfunc");
    debug!(path = %fallback.display(), "using fallback zsh completions directory");

    fs::create_dir_all(&fallback)?;

    Ok(fallback)
}

pub fn zsh_completions_script() -> &'static str {
    indoc! {r#"
        #compdef kcm

        _kcm() {
            local -a completions
            local -a prev_words
            local hint line
            prev_words=("${(@)words[2,$CURRENT-1]}")
            while IFS= read -r line; do
                if [[ "$line" == '#'* ]]; then
                    hint="${line:1}"
                elif [[ -n "$line" ]]; then
                    completions+=("$line")
                fi
            done < <(kcm completions complete "--cur=${PREFIX}" -- "${prev_words[@]}" 2>/dev/null)
            compadd -a completions
            [[ -n "$hint" ]] && compadd -x "$hint"
        }

        compdef _kcm kcm
    "#}
}

pub fn print_script(shell: Option<ShellKind>) -> Result<()> {
    let shell = match shell {
        Some(x) => x,
        None => {
            let shell = env::var("SHELL").unwrap_or_default();
            if shell.ends_with("zsh") {
                ShellKind::Zsh
            } else if shell.ends_with("bash") {
                ShellKind::Bash
            } else {
                return Err(Error::UnsupportedShell);
            }
        }
    };
    let script = match shell {
        ShellKind::Bash => bash_completions_script(),
        ShellKind::Zsh => zsh_completions_script(),
    };

    out!("{script}");

    Ok(())
}

pub fn install() -> Result<()> {
    let shell = env::var("SHELL").unwrap_or_default();
    let (script, path) = if shell.ends_with("zsh") {
        let script = zsh_completions_script();
        let dir = find_zsh_completions_dir()?;

        fs::create_dir_all(&dir)?;

        (script, dir.join("_kcm"))
    } else if shell.ends_with("bash") {
        let script = bash_completions_script();
        // ~/.local/share/bash-completion/completions/ is XDG standard
        let dir = dirs::data_dir()
            .ok_or(Error::InvalidConfigDir)?
            .join("bash-completion")
            .join("completions");

        fs::create_dir_all(&dir)?;

        (script, dir.join("kcm"))
    } else {
        return Err(Error::UnsupportedShell);
    };

    fs::write(&path, script)?;

    out!("Installed completions to {}", path.display());

    Ok(())
}

pub fn complete(cur: &str, words: &[String]) {
    let mut node = Commands::completion_node();
    let mut positionals_seen: usize = 0;
    let mut skip_next = false;

    for word in words {
        if skip_next {
            // This word is the value of the previous flag — not a positional.
            skip_next = false;
            continue;
        }
        if word.starts_with('-') {
            // `--flag value` form: if the flag is a known named arg, the next word is its value.
            // `--flag=value` form: value is embedded, no skip needed.
            if !word.contains('=') && node.args.contains(&word.as_str()) {
                skip_next = true;
            }
            continue;
        }
        if let Some((_, sub_fn)) = node.subcommands.iter().find(|(n, _)| *n == word.as_str()) {
            node = sub_fn();
            positionals_seen = 0; // reset when we descend into a subcommand
        } else {
            positionals_seen += 1; // positional argument consumed
        }
    }

    // If the last word is a bare flag name (no `=`), the cursor is completing its value.
    let awaiting_flag_value = words
        .last()
        .is_some_and(|w| w.starts_with('-') && !w.contains('='));

    if cur.starts_with('-') {
        // User is typing a flag — emit only --long args that match the prefix.
        for arg in &node.args {
            if arg.starts_with(cur) {
                println!("{arg}");
            }
        }
    } else if awaiting_flag_value {
        // Cursor is the value slot for a flag — no static completions from us.
    } else if !node.commands.is_empty() {
        // Static sub-command names.
        for cmd in &node.commands {
            if cmd.starts_with(cur) {
                println!("{cmd}");
            }
        }
    } else if positionals_seen == 0 {
        // Leaf node with unfilled positional: ask the API for matching values.
        if let Some(values_fn) = node.values {
            let values = values_fn(cur, words);
            let has_more = values.len() == COMPLETION_PAGE_SIZE as usize;
            for v in &values {
                println!("{v}");
            }
            if has_more {
                println!("# keep typing to narrow results");
            }
        }
    }
    // positionals_seen > 0: positional already filled — emit nothing.
}
