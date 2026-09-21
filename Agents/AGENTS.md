# Agent Instructions

Read this file before starting any task in this repo. These rules apply regardless of what the specific task asks for.

## 1. Do exactly what's asked — nothing more

Do not improvise, "improve," restructure, rename, or clean up anything that wasn't explicitly part of the current task. If you notice something adjacent that seems worth fixing, mention it in your summary — don't just fix it. Scope creep is the most expensive kind of mistake here: it's harder to review, harder to trust, and harder to undo cleanly.

This applies even if you're confident the extra change is correct or obviously better. "Obviously better" is a decision for the human to make, not you.

## 2. If there's a choice to make, ask — don't decide silently

If a task has more than one reasonable way to implement it, and the task didn't specify which, stop and ask before proceeding — even if you have a preference or a "best practice" opinion. Present the options plainly (a short list is fine) and wait for an answer.

Do not pick the option you think is best and mention the other options only in the summary afterward. By then the decision has already been made without input.

The only exception: purely mechanical choices with no real tradeoff (variable naming that doesn't matter, formatting that follows the existing style) don't need to be escalated. If you're unsure whether something counts as "a real choice," treat it as one and ask.

## 3. No test frameworks, smoke tests, or scaffolding unless explicitly asked

Do not add test frameworks, smoke-test scripts, Python test files, headless-browser tests, or any test scaffolding on your own initiative — not even "just to verify this works," not even small ones. If the task needs verification, use the simplest possible manual check: a type-check (`tsc --noEmit`), a grep, a plain `curl`/manual run, or reading the code carefully. Describe what you checked in your summary.

Only build a real test suite (a testing framework, organized test files, CI wiring) when it is explicitly requested as its own task. When it is requested, treat it as a real task worth doing properly — this rule is about not doing it uninvited, not about doing it badly when asked.

## 4. Read the project's own docs first

Before writing any code, read whatever architecture/reference docs already exist in the repo (e.g. `doc/freeauth-architecture.md`, `doc/backend.md`, `doc/ui-guide.md` — check what's actually there, names may vary). These documents are the source of truth for conventions, contracts, and prior decisions. If something you're about to do conflicts with what's written there, stop and flag the conflict rather than picking one side yourself.

If you make a decision or change something that these docs describe, update the docs in the same task — don't leave them stale for someone else to notice later.

## 5. Report honestly, including what you're unsure about

When you finish a task, explicitly separate:
- what you're confident is correct and complete
- what you're unsure about, or where you made a judgment call
- anything you found that seems off, inconsistent, or incomplete, even if it's outside this task's scope

Never present a guess as a confirmed fact. If you couldn't verify something (e.g. no live database, no way to get a real OAuth token), say so plainly and describe how it *would* be verified, rather than asserting it works.

## 6. Stay inside the task's boundaries

If a task says "core and adapters only, no Express changes" (or similar), treat that boundary as firm. Don't touch files outside it even if it would make the task easier or the result more complete. If the boundary itself seems wrong for what's being asked, say so — don't quietly cross it.

## 7. Never run destructive or system-wide commands without asking first

Never run cache-clearing, global uninstalls, recursive deletes, or anything that affects files/state outside this project's own folder — even to fix a blocking error (like a full disk or a broken install). If you hit a wall like that, stop and explain the problem and the fix you'd propose; don't just run it.

## 8. Match the existing style, don't introduce your own

Follow the coding style, naming conventions, and patterns already established in the codebase (indentation, quote style, comment density, error-handling patterns, etc.), even if you'd personally write it differently. Consistency with what's already there beats "correctness" by your own taste.
