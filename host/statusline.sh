#!/bin/sh
input=$(cat)
used=$(echo "$input" | jq -r '.context_window.used_percentage // empty')
in_tok=$(echo "$input" | jq -r '.context_window.total_input_tokens // empty')
out_tok=$(echo "$input" | jq -r '.context_window.total_output_tokens // empty')
cost=$(echo "$input" | jq -r '.cost.total_cost_usd // empty')
model=$(echo "$input" | jq -r '.model.display_name // empty')

fmt() {
  # 12345 -> 12.3k, 1234567 -> 1.2M
  n=$1
  if [ "$n" -ge 1000000 ]; then awk -v n="$n" 'BEGIN{printf "%.1fM", n/1000000}'
  elif [ "$n" -ge 1000 ]; then awk -v n="$n" 'BEGIN{printf "%.1fk", n/1000}'
  else printf '%s' "$n"; fi
}

if [ -n "$used" ]; then
  used_int=$(printf '%.0f' "$used")
  if [ "$used_int" -ge 90 ]; then bar="!!!"
  elif [ "$used_int" -ge 75 ]; then bar="^^^"
  else bar="   "; fi
  out="$bar ctx: ${used_int}% used"
else
  out="ctx: --"
fi

if [ -n "$in_tok" ] && [ -n "$out_tok" ]; then
  total=$((in_tok + out_tok))
  out="$out | tokens: $(fmt "$total") (in $(fmt "$in_tok") / out $(fmt "$out_tok"))"
fi
[ -n "$cost" ] && out="$out | \$$(printf '%.2f' "$cost")"
[ -n "$model" ] && out="$out | $model"

# --- sandbox: read from the settings files (the CONFIG, not a live feed)
proj=$(echo "$input" | jq -r '.workspace.project_dir // .cwd // empty')
files="$HOME/.claude/settings.json"
for f in "$proj/.claude/settings.json" "$proj/.claude/settings.local.json"; do
  [ -f "$f" ] && files="$files $f"
done
sbx=$(jq -rs '
  (map(.sandbox.enabled) | map(select(. != null)) | last) as $on |
  (map(.sandbox.allowUnsandboxedCommands) | map(select(. != null)) | last) as $esc |
  (map(.permissions.ask // []) | add | any(. == "Bash(dangerouslyDisableSandbox:true)")) as $askme |
  if $on != true then "sbx: OFF"
  elif $esc == false then "sbx: STRICT (no exits)"
  elif $askme then "sbx: ON, exits ask you"
  else "sbx: ON, exits ask classifier" end' $files 2>/dev/null)
[ -n "$sbx" ] && out="$out | $sbx"

# --- subagents active in the last 2 min: their current context size
tp=$(echo "$input" | jq -r '.transcript_path // empty')
sub="${tp%.jsonl}/subagents"
if [ -n "$tp" ] && [ -d "$sub" ]; then
  ag=""
  for f in $(find "$sub" -name 'agent-*.jsonl' -mmin -2 2>/dev/null); do
    c=$(tail -n 40 "$f" | jq -R 'fromjson? | .message.usage? | select(.)
          | .input_tokens + (.cache_read_input_tokens // 0) + (.cache_creation_input_tokens // 0)' 2>/dev/null | tail -1)
    [ -n "$c" ] && ag="$ag $(fmt "$c")"
  done
  [ -n "$ag" ] && out="$out | agents ctx:$ag"
fi
printf '%s' "$out"
