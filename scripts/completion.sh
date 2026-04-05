#!/usr/bin/env bash
# Passage shell completion installer
# Usage: source scripts/completion.sh   OR   add to ~/.bashrc / ~/.zshrc

_passage_install_completion() {
    local shell="$1"

    if [[ "$shell" == "bash" ]]; then
        if command -v passage &>/dev/null; then
            eval "$(passage --install-completion bash 2>/dev/null)" || true
            echo "Bash completion installed. Restart your shell or run: source ~/.bashrc"
        else
            echo "passage not found in PATH. Install it first."
        fi

    elif [[ "$shell" == "zsh" ]]; then
        if command -v passage &>/dev/null; then
            eval "$(passage --install-completion zsh 2>/dev/null)" || true
            echo "Zsh completion installed. Restart your shell or run: source ~/.zshrc"
        else
            echo "passage not found in PATH. Install it first."
        fi

    else
        echo "Usage: $0 [bash|zsh]"
    fi
}

# If sourced directly, attempt auto-detection
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed, not sourced
    SHELL_NAME="$(basename "$SHELL")"
    _passage_install_completion "$SHELL_NAME"
else
    # Sourced – install for current shell
    SHELL_NAME="$(basename "$SHELL")"
    _passage_install_completion "$SHELL_NAME"
fi

# Manual completion for bash (fallback if --install-completion unavailable)
_passage_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="add list ls edit remove check report generate gen audit config remind --help --version"
    COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
}

complete -F _passage_completions passage
