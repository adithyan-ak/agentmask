/**
 * Common utilities for hook handlers.
 *
 * Hook contract:
 *   - Receives JSON on stdin
 *   - Exit 0 = allow
 *   - Exit 2 = block
 *   - Exit 1 (or any other) = non-blocking warning (graceful degradation)
 *
 * The --format flag selects the I/O adapter:
 *   claude (default): stderr for block messages, { hookSpecificOutput } on stdout
 *   cursor:           { permission, agentMessage } on stdout
 */

export interface HookInput {
  session_id?: string;
  cwd?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: string;
  hook_event_name?: string;
}

type HookFormat = "claude" | "cursor";

function parseFormat(): HookFormat {
  const idx = process.argv.indexOf("--format");
  if (idx !== -1 && process.argv[idx + 1] === "cursor") return "cursor";
  return "claude";
}

function readRawStdin(): Promise<any> {
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

function normalizeCursorInput(raw: any): HookInput {
  // Cursor sends workspace_roots[] instead of cwd,
  // command at top level for shell hooks,
  // tool_output instead of tool_response.
  const cwd =
    raw.workspace_roots?.[0] ??
    process.env.CURSOR_PROJECT_DIR ??
    raw.cwd ??
    process.cwd();

  const toolInput =
    raw.tool_input ??
    (raw.command != null ? { command: raw.command } : undefined) ??
    (raw.file_path != null ? { file_path: raw.file_path } : undefined);

  return {
    session_id: raw.conversation_id ?? raw.session_id,
    cwd,
    tool_name: raw.tool_name,
    tool_input: toolInput,
    tool_response: raw.tool_output ?? raw.tool_response,
    hook_event_name: raw.hook_event_name,
  };
}

export async function readStdin(): Promise<HookInput> {
  const raw = await readRawStdin();
  if (parseFormat() === "cursor") return normalizeCursorInput(raw);
  return raw;
}

/** Block the tool call. */
export function block(message: string): never {
  if (parseFormat() === "cursor") {
    process.stdout.write(
      JSON.stringify({ permission: "deny", agentMessage: message }),
    );
  } else {
    process.stderr.write(message);
  }
  process.exit(2);
}

/** Allow the tool call, optionally with additional context. */
export function allow(additionalContext?: string): void {
  const format = parseFormat();
  if (format === "cursor") {
    const output: Record<string, string> = { permission: "allow" };
    if (additionalContext) output.agentMessage = additionalContext;
    process.stdout.write(JSON.stringify(output));
  } else if (additionalContext) {
    process.stdout.write(
      JSON.stringify({ hookSpecificOutput: { additionalContext } }),
    );
  }
  process.exit(0);
}

/** Safety timeout — never let a hook run longer than 4s (hook timeout is 5s). */
export function startSafetyTimer(ms = 4000): void {
  setTimeout(() => {
    process.exit(1);
  }, ms).unref();
}
