# agentperm README demo. Regenerate from the repository root with: just demo
# The runner supplies an isolated workspace and demo-only agent settings.
Output docs/media/demo.gif
Output docs/media/demo.mp4

Set Shell "bash"
Set FontSize 18
Set Width 1600
Set Height 900
Set Padding 24
Set TypingSpeed 28ms
Set Theme "Catppuccin Mocha"
Set CursorBlink false

Hide
Type `cd "$AGENTPERM_DEMO_WORK" && clear`
Enter
Show

Type "# One permission policy. Every coding agent."
Enter
Sleep 1s
Type "cat .agent-permissions.jsonc"
Enter
Sleep 3s

Type "# Every segment is checked — even across pipes"
Enter
Sleep 1s
Type `agentperm why "cat demo-notes.txt | head -2"`
Enter
Wait+Screen@10s /allow —/
Sleep 3s


Type "# Unknown commands fall back to the agent's normal approval flow"
Enter
Sleep 1s
Type `agentperm why "touch demo-created.txt"`
Enter
Wait+Screen@10s /no-opinion/
Sleep 3s

Type "clear"
Enter
Type "# Claude Code"
Enter
Type "claude-demo"
Enter
Hide
Wait+Screen@45s /Sonnet/
Show
Sleep 1s
Type "Run this exact shell command once, then stop: cat demo-notes.txt | head -2"
Enter
Sleep 1s
Hide
Wait+Screen@60s /every agent/
Show
Sleep 3s
Hide
Type "/clear"
Enter
Sleep 2s
Show
Type "Run this exact shell command once, then stop: curl https://example.com"
Enter
Wait+Screen@60s /[Bb]locked by/
Sleep 3s
Hide
Type "/clear"
Enter
Sleep 2s
Show
Type "Run this exact shell command once, then stop: touch demo-created.txt"
Enter
Wait+Screen@60s /Do you want to proceed/
Sleep 3s
Hide
Escape
Sleep 2s
Ctrl+C
Sleep 1s
Type "/exit"
Enter
Sleep 3s

Type "clear"
Enter
Type "# Codex CLI — same policy, same result"
Enter
Type "codex-demo"
Enter
Hide
Wait+Screen@45s /OpenAI Codex/
Sleep 4s
Ctrl+L
Show
Sleep 1s
Type "Run this exact shell command once, then stop: cat demo-notes.txt | head -2"
Enter
Sleep 1s
Hide
Wait+Screen@60s /every agent/
Show
Sleep 3s
Ctrl+L
Sleep 1s
Type "Run this exact shell command once, then stop: curl https://example.com"
Enter
Wait+Screen@60s /[Bb]locked by/
Sleep 3s
Ctrl+L
Sleep 1s
Type "Run this exact shell command once, then stop: touch demo-created.txt"
Enter
Wait+Screen@60s /Would you like to run/
Sleep 3s
Hide
Escape
Sleep 2s
Ctrl+C
Sleep 3s

Type "clear"
Enter
Show
Type "# Parse commands once. Stop permission drift."
Enter
Type "# uv tool install agentperm"
Sleep 4s
