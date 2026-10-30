/**
 * LangChain.js + Tenuo — protected-tool demo entry point.
 *
 * Runs the allowed and denied scenarios from `protected-tool.ts` and prints
 * the transcript. No model, API key, or network.
 *
 * The dev root mints warrants without key material and refuses production.
 * It reads TENUO_ALLOW_DEV when `createTenuo.devRoot()` is called, so setting
 * it here, before `runDemo()`, opts this local run in.
 */
import { runDemo } from "./protected-tool.ts";

process.env.TENUO_ALLOW_DEV ??= "1";
await runDemo();
