# agentperm README demo. Regenerate from the repo root with: just demo
# Requires vhs (https://github.com/charmbracelet/vhs) and a synced .venv.
Output docs/media/demo.gif

Set Shell "bash"
Set FontSize 21
Set Width 1400
Set Height 700
Set Padding 24
Set TypingSpeed 35ms
Set Theme "Catppuccin Mocha"

# Deterministic sandbox: fresh HOME and cwd, local build on PATH.
Hide
Type `export PATH="$PWD/.venv/bin:$PATH" && rm -rf /tmp/agentperm-demo && mkdir -p /tmp/agentperm-demo/home /tmp/agentperm-demo/work && export HOME=/tmp/agentperm-demo/home && cd /tmp/agentperm-demo/work && clear`
Enter
Sleep 1s
Show

Type "# one permission policy for Claude Code, Codex, OpenCode, Gemini CLI & Kiro"
Enter
Sleep 1.5s

Type "agentperm init"
Enter
Sleep 2.5s

Type `agentperm why "git status | head -5"`
Enter
Sleep 3.5s

Type `agentperm why "cat notes.txt | ./deploy.sh"`
Enter
Sleep 3.5s

Type `agentperm why "sudo rm -rf /"`
Enter
Sleep 3s

Type "# uv tool install agentperm"
Sleep 3s
