// Type stubs for openclaw/plugin-sdk/core
// These are provided at runtime by the OpenClaw host environment.
// This file exists only to allow standalone TypeScript compilation.

declare module "openclaw/plugin-sdk/core" {
  export interface OpenClawPluginApi {
    logger: {
      info?: (msg: string) => void;
      warn: (msg: string) => void;
      error: (msg: string) => void;
    };
    config: unknown;
    on(event: "before_tool_call", handler: (event: PluginHookBeforeToolCallEvent, ctx: PluginHookToolContext) => Promise<PluginHookBeforeToolCallResult | void>, options?: { priority?: number }): void;
    on(event: "after_tool_call", handler: (event: PluginHookAfterToolCallEvent, ctx: PluginHookToolContext) => Promise<void>): void;
    on(event: "message_received", handler: (event: PluginHookMessageReceivedEvent, ctx: PluginHookMessageContext) => Promise<void>): void;
    on(event: "gateway_start", handler: (event: { port: number }) => Promise<void>): void;
    registerTool(factory: () => ToolDefinition, meta: { name: string }): void;
    resolvePath(relativePath: string): string;
  }

  export interface PluginHookBeforeToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
  }

  export interface PluginHookBeforeToolCallResult {
    block: boolean;
    blockReason?: string;
  }

  export interface PluginHookAfterToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
    result?: unknown;
    error?: string;
    runId?: string;
    durationMs?: number;
  }

  export interface PluginHookToolContext {
    sessionKey: string;
    runId?: string;
  }

  export interface PluginHookMessageReceivedEvent {
    content: string;
    from: string;
  }

  export interface PluginHookMessageContext {
    channelId: string;
  }

  export interface ToolDefinition {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, unknown>;
      required?: string[];
    };
    execute(params: Record<string, unknown>): Promise<string>;
  }

  export function emptyPluginConfigSchema(): unknown;
}
