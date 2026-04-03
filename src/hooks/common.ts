/**
 * Common utilities for Claude Code hook handlers.
 *
 * Hook contract:
 *   - Receives JSON on stdin
 *   - Exit 0 = allow (stdout parsed as JSON for hookSpecificOutput)
 *   - Exit 2 = block (stderr shown to Claude as error message)
 *   - Exit 1 (or any other) = non-blocking warning (graceful degradation)
 */

export interface HookInput {
  session_id?: string;
  cwd?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: string;
  hook_event_name?: string;
}

export async function readStdin(): Promise<HookInput> {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        resolve({});
      }
    });
    process.stdin.on("error", reject);
  });
}

/** Block the tool call. Stderr message is shown to Claude. */
export function block(message: string): never {
  process.stderr.write(message);
  process.exit(2);
}

/** Allow the tool call, optionally with additional context. */
export function allow(additionalContext?: string): void {
  if (additionalContext) {
    const output = {
      hookSpecificOutput: { additionalContext },
    };
    process.stdout.write(JSON.stringify(output));
  }
  process.exit(0);
}

/** Safety timeout — never let a hook run longer than 4s (hook timeout is 5s). */
export function startSafetyTimer(ms = 4000): void {
  setTimeout(() => {
    process.exit(1); // Non-blocking exit — degrade gracefully
  }, ms).unref();
}
