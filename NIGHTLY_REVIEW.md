[NANOBOT_HINDSIGHT_NIGHTLY]

# Nightly Hindsight review

Call `hindsight_automation` exactly once with `action="nightly_review"`.

Do not call any other tool. Do not read files or evidence, call raw Hindsight tools, inspect or edit skills, create a Git branch, commit, push, merge, or modify configuration.

The plugin performs the bounded Hindsight Reflect call, validates its structured result, and writes the sanitized report internally. Return a concise status using only the result of the one plugin call.
