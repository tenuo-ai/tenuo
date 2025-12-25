/* tslint:disable */
/* eslint-disable */

export function check_access(warrant_b64: string, tool: string, args_json: any, trusted_root_hex: string, dry_run: boolean): any;

/**
 * Check authorization with a real PoP signature
 */
export function check_access_with_pop(warrant_b64: string, tool: string, args_json: any, trusted_root_hex: string, pop_signature_hex: string): any;

export function check_chain_access(warrant_b64_list: string[], tool: string, args_json: any, trusted_root_hex: string): any;

/**
 * Create a fresh sample warrant with the given tool and TTL
 * This generates new keys each time, ensuring the warrant is never expired
 */
export function create_sample_warrant(tool: string, constraint_field: string, constraint_pattern: string, ttl_seconds: bigint): any;

export function decode_warrant(base64_warrant: string): any;

/**
 * Generate a new Ed25519 keypair for testing PoP
 */
export function generate_keypair(): any;

export function init_panic_hook(): void;

/**
 * Create a Proof-of-Possession signature for a warrant
 */
export function sign(private_key_hex: string, warrant_b64: string, tool: string, args_json: any): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly check_access: (a: number, b: number, c: number, d: number, e: any, f: number, g: number, h: number) => any;
  readonly check_access_with_pop: (a: number, b: number, c: number, d: number, e: any, f: number, g: number, h: number, i: number) => any;
  readonly check_chain_access: (a: number, b: number, c: number, d: number, e: any, f: number, g: number) => any;
  readonly create_sample_warrant: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => any;
  readonly decode_warrant: (a: number, b: number) => any;
  readonly generate_keypair: () => any;
  readonly sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: any) => any;
  readonly init_panic_hook: () => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
