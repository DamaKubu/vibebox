---
name: codecard
description: >
  Flashcard-style game to learn a codebase by explanation and grading. Pick a random
  function from a scope the user defines, ask them to explain it, grade the answer,
  reveal the correct one in depth, then next round. Use when the user says "teach me
  this code", "let's learn this codebase", "flashcard", "study this", "/codecard",
  "code learning game", or "make this a learning game". Also use when continuing a
  prior game ("next round", "another", "round N").
---

# codecard — code flashcard game

A learning loop: random function from a chosen scope → user explains → graded → correct answer revealed → next round. Goal: durable understanding of a real codebase the user is working on, not memorization.

## How a session goes

```
User: scope client_v10            ← sets the file/dir to draw from
You:  Round 1: detect.py — Tracker.update()
      [show the function code, with line numbers]
      Tell me: what is it, what does it do, how does it work,
      how would you modify it?
User: [explains in their own words, may skip questions]
You:  Grade: 7/10
      Right: matches detections to tracks, prunes lost
      Missed: greedy nearest-neighbor specifically, alpha=0.7 smoothing,
              filter_untracked returns ONLY best confirmed track when >1
      Correct answer:
      [detailed walkthrough — this is where the learning happens]
      Round 2?
```

## Scope command

User types `scope <thing>`. Resolve to a real path:

- `scope client_v10` → `client_v10/` directory
- `scope detect.py` → that file
- `scope core/postflight.py:compare_predicted_actual` → that one function
- `scope tspdrone planning` → fuzzy match — find planning-related files in tspdrone

If ambiguous, ask. If clear, confirm in one line: `Scope: client_v10/ (8 files, ~50 functions in pool)` and start Round 1.

User can switch scope any time. `rescope <thing>` or just `scope <thing>` again.

## Picking the function

Pick **substantive** functions. Skip:

- One-line getters / setters
- `__init__` that only stores args
- Trivial dataclass `__post_init__` validators (boring, repetitive across project)
- Pure-syntax wrappers

Prefer:

- Functions with real logic (loops, branches, state machines)
- Functions with non-obvious tricks (the `alpha=0.7` smoothing, the `int|1` odd-kernel trick, the `_PLAUSIBLE_LO/HI` clamp)
- Functions tied to project concepts (mask handling, calibration, Kalman, TSP cost)

Mix difficulty. Don't pick the hardest function every round; mix easy/medium/hard so the user gets wins.

Don't repeat a function within a session unless the user asks. Keep a running list in your head of what was covered.

## The 4 questions

Ask all four, but accept partial answers — the user is learning, not being interrogated:

1. **What is it?** — what's it called, what type of code (parser? handler? math?)
2. **What does it do?** — the contract (inputs → outputs, side effects)
3. **How does it work?** — the mechanism (algorithm, key tricks, why this approach)
4. **How would you modify it?** — extension thinking (what if X changed, alternate impls)

If the user answers casually with one paragraph covering 2 of the 4, grade what they said. Don't dock points for not following the format.

## Grading

Score out of 10. Be honest but kind. Examples:

- **9-10**: Got the mechanism and the why, named the tricky bits
- **6-8**: Got the contract, missed some mechanism detail
- **3-5**: General idea right, mechanism wrong
- **0-2**: Misread the function or guessed

Format:

```
Grade: 7/10
✓ Right:  [what they got]
✗ Missed: [specific things — line refs welcome]
```

Don't pad. If they nailed it, say so and move on.

## The correct answer

**This is the point of the game.** Be thorough. The user wants to understand, not just be graded.

- Walk the function top-to-bottom
- Name every non-obvious choice (`why alpha=0.7?`, `why bitwise OR with 1?`, `why this exception swallowed?`)
- Tie to project concepts (`this is the mask-at-source pattern from pipeline._loop`)
- Reference related files (`see also trackers.py:_KTrack`)
- Comments in the file often explain *why* — point them out if the user missed

When the function has a known bug, gotcha, or refactor history (look at comments mentioning rounds, traps, "pre-X this did Y"), surface that — it's the most valuable context.

## Round flow

After revealing the answer, end with: `Round N+1?` (no question about it — assume yes, the user can stop by saying anything else).

If the user says "harder" / "easier" / "different file", adjust pool selection but stay in the same scope.

If the user asks a question instead of answering (e.g. "wait what does cv2.findContours return?"), **break out of game mode** — answer the question fully, then ask if they want to resume.

## Anti-patterns

- Don't pick the same function twice in a session
- Don't pick a one-line wrapper
- Don't grade harshly on a function they couldn't reasonably know without the code
- Don't dump 200 lines of code without highlighting what matters
- Don't skip the "correct answer" — that's where learning happens
- Don't treat partial answers as failures — give credit for what's right
- Don't ramble in grading — keep it tight, save depth for the correct-answer section

## Stopping

User says "stop", "enough", "later", "done" — exit cleanly. Offer a one-line summary: "Covered N functions across {scope}. Strongest area: X. Weakest: Y."

## Continuation

If the user invokes the skill again in a later session, ask: "Resume from {last scope}, or new scope?" Don't assume; sessions can be days apart.
