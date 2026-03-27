// Type stubs for standalone claws-defender builds.
// These are provided at runtime by the OpenClaw host environment.
// This file exists only to allow standalone TypeScript compilation.

declare module "openclaw/plugin-sdk/plugin-entry" {
  export type OpenClawConfig = {
    agents?: {
      defaults?: {
        workspace?: string;
      };
    };
  };

  export interface OpenClawPluginApi {
    logger: {
      info?: (msg: string) => void;
      warn: (msg: string) => void;
      error: (msg: string) => void;
    };
    config: OpenClawConfig;
    pluginConfig?: Record<string, unknown>;
    runtime: {
      agent: {
        resolveAgentTimeoutMs(params: { cfg?: OpenClawConfig }): number;
        runEmbeddedPiAgent(params: {
          sessionId: string;
          sessionFile: string;
          workspaceDir: string;
          config?: OpenClawConfig;
          prompt: string;
          timeoutMs: number;
          runId: string;
          agentDir?: string;
          disableTools?: boolean;
        }): Promise<{
          payloads?: Array<{
            text?: string;
            content?: string;
            message?: unknown;
            isError?: boolean;
          }>;
        }>;
      };
    };
    on(event: "before_tool_call", handler: (event: {
      toolName: string;
      params: Record<string, unknown>;
      runId?: string;
      toolCallId?: string;
    }, ctx: {
      sessionKey?: string;
      runId?: string;
      toolName?: string;
      toolCallId?: string;
    }) => Promise<{ params?: Record<string, unknown>; block?: boolean; blockReason?: string } | void>, options?: { priority?: number }): void;
    on(event: "after_tool_call", handler: (event: {
      toolName: string;
      params: Record<string, unknown>;
      result?: unknown;
      error?: string;
      runId?: string;
      toolCallId?: string;
      durationMs?: number;
    }, ctx: {
      sessionKey?: string;
      runId?: string;
      toolName?: string;
      toolCallId?: string;
    }) => Promise<void>): void;
    on(event: "message_received", handler: (event: {
      content: string;
      from: string;
      timestamp?: number;
      metadata?: Record<string, unknown>;
    }, ctx: {
      channelId: string;
      accountId?: string;
      conversationId?: string;
    }) => Promise<void>): void;
    on(event: "gateway_start", handler: (event: { port: number }) => Promise<void>): void;
    registerTool(tool: import("openclaw/plugin-sdk/agent-runtime").AnyAgentTool): void;
    resolvePath(relativePath: string): string;
  }

  export function definePluginEntry(definition: {
    id: string;
    name: string;
    description: string;
    configSchema?: unknown;
    register(api: OpenClawPluginApi): void;
  }): unknown;
  export function emptyPluginConfigSchema(): unknown;
}

declare module "openclaw/plugin-sdk/agent-runtime" {
  export type AnyAgentTool = {
    name: string;
    label?: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, unknown>;
      required?: string[];
    };
    execute(
      toolCallId: string,
      params: Record<string, unknown>,
      signal?: AbortSignal,
      onUpdate?: unknown,
    ): Promise<unknown>;
  };

  export function textResult<TDetails>(text: string, details: TDetails): unknown;
}
