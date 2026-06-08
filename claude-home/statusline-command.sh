#!/bin/sh
input=$(cat)
used=$(echo "$input" | jq -r '.context_window.used_percentage // empty')
total=$(echo "$input" | jq -r '.context_window.total_input_tokens // empty')
size=$(echo "$input" | jq -r '.context_window.context_window_size // empty')
model=$(echo "$input" | jq -r '.model.display_name // empty')

if [ -n "$used" ]; then
  used_int=$(printf '%.0f' "$used")
  if [ "$used_int" -ge 90 ]; then
    bar="!!!"
  elif [ "$used_int" -ge 75 ]; then
    bar="^^^"
  else
    bar="   "
  fi
  if [ -n "$total" ] && [ -n "$size" ]; then
    printf "%s ctx: %s%% used (%s / %s tokens)" "$bar" "$used_int" "$total" "$size"
  else
    printf "%s ctx: %s%% used" "$bar" "$used_int"
  fi
else
  if [ -n "$model" ]; then
    printf "ctx: -- | %s" "$model"
  else
    printf "ctx: --"
  fi
fi
