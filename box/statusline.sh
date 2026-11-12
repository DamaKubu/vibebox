#!/bin/sh
# Status line for Claude Code INSIDE the vibe box (same look as on the host):
# context %, tokens, cost, model, the box's network, and live subagent contexts.
input=$(cat)
used=$(echo "$input" | jq -r '.context_window.used_percentage // empty')
in_tok=$(echo "$input" | jq -r '.context_window.total_input_tokens // empty')
out_tok=$(echo "$input" | jq -r '.context_window.total_output_tokens // empty')
cost=$(echo "$input" | jq -r '.cost.total_cost_usd // empty')
model=$(echo "$input" | jq -r '.model.display_name // empty')

fmt() {
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
  out="$out | tokens: $(fmt $((in_tok + out_tok))) (in $(fmt "$in_tok") / out $(fmt "$out_tok"))"
fi
[ -n "$cost" ] && out="$out | \$$(printf '%.2f' "$cost")"
[ -n "$model" ] && out="$out | $model"

# The box itself is the sandbox: show what it can reach (set by vibe).
out="$out | vibe box, net: ${VIBEBOX_NET:-?}"

# Subagents active in the last 2 min: their current context size.
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
