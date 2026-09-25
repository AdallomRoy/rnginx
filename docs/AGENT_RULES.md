# Rules for porting agents (read fully before starting)

You are one of several agents porting nginx 1.31.7 from C to Rust, working in parallel, each
in its own git worktree and branch. Also read CONVENTIONS.md and PORTING.md in the repo root.

Locations (nginx-c and nginx-tests are NOT in git; always use these absolute paths):
- C source: /home/ubuntu/rnginx/nginx-c/src ; reference C binary: /home/ubuntu/rnginx/nginx-c/objs/nginx
- Tests: /home/ubuntu/rnginx/nginx-tests (Perl, Test::Nginx). docs/c-pass.txt lists the 478 files that pass with the C binary.
- Your worktree is your cwd; build with `cargo build` (debug profile, opt-level 1; fastest for iteration).

Porting standard: port the C faithfully — same directives and flags, same defaults, same log
messages (tests grep error.log), same header order and response bytes, same status codes and
timeouts. Read the C function and port it; do not invent behaviour. The runtime model is
async (tokio current-thread, Rc/RefCell, see CONVENTIONS.md): C event handlers become `.await`
points; state machines become async loops. Never hold a RefCell borrow across an `.await`.

Ownership and merge discipline (critical — branches are merged one by one into master):
- Edit only the files you own (listed in your assignment) plus the minimal registration lines
  in `crates/ngx-http/src/lib.rs` (`pub mod x;` and switching one line in `modules()` from
  `stubs::x_module()` to `x::x_module()`). Never reorder `modules()`.
- Changes to shared core files (crates/ngx-core/*, core.rs, core_rt.rs, request.rs,
  request_rt.rs, request_body.rs, variables.rs, script.rs, lib.rs helpers, buf.rs, connection.rs)
  must be small and strictly additive: add fields, functions, hooks; never rename, remove,
  reorder or change signatures of existing items. Keep diffs minimal; do not reformat files.
  List every core change in your final report.
- Do not modify anything under nginx-tests or nginx-c. Do not add crate dependencies beyond
  those listed in CONVENTIONS.md without a strong reason (say so in the report).

Build/test loop:
- `cargo build 2>&1 | grep -E "^error" -A8` must be empty before every commit.
- Run tests with a timeout (some failures hang):
  `cd /home/ubuntu/rnginx/nginx-tests && TEST_NGINX_BINARY=$WT/target/debug/nginx timeout 300 prove -v foo.t`
  (`$WT` = your worktree path). `TEST_NGINX_LEAVE=1` keeps /tmp/nginx-test-XXXX with error.log (debug level).
- When unsure what the expected behaviour is, run the same test with the C binary and diff the
  responses (`TEST_NGINX_BINARY=/home/ubuntu/rnginx/nginx-c/objs/nginx`).
- Several agents share this 8-core machine: do not run the whole suite; run your own tests.
- Never claim a test passes without having run it.

Commits: commit early and often on your branch (`git add <specific files>`; `git commit -m ...`).
The branch must compile at the end. If you run low on context, commit a compiling state and
report exactly what is done and what remains, so a follow-up agent can continue.

Final report (this is all the orchestrator sees): (1) per-test result table from real runs
(file → ok / N failed / not started, and why), (2) every core/shared file you touched and what
changed, (3) known gaps and suggested next steps.
