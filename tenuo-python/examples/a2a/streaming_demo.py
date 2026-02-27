#!/usr/bin/env python3
"""
A2A Streaming Demo

Demonstrates streaming task responses with Server-Sent Events (SSE).
Shows progress updates, intermediate results, and completion events.

Use cases:
- Long-running analysis tasks
- Incremental data processing
- Real-time progress reporting
- Large file processing with chunks

Run:
    python streaming_demo.py
"""

import asyncio
import io
import sys
import time
from pathlib import Path

# Ensure we can import from tenuo
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tenuo import Range, SigningKey, Subpath, Warrant
from tenuo.a2a import A2AClient, A2AServer


# Colors for output
class C:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def log(msg: str, color: str = C.CYAN):
    print(f"{color}{msg}{C.RESET}")


def header(text: str):
    print(f"\n{C.BOLD}{C.YELLOW}{'='*70}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}{text.center(70)}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}{'='*70}{C.RESET}\n")


# =============================================================================
# Server (Worker Agent)
# =============================================================================

def create_analysis_server(signing_key: SigningKey, trusted_issuers: list, port: int = 8000) -> A2AServer:
    """Create analysis agent that streams results."""

    server = A2AServer(
        name="Analysis Agent",
        url=f"http://localhost:{port}",
        public_key=signing_key.public_key,
        trusted_issuers=trusted_issuers,
        require_warrant=True,
        require_audience=False,
        require_pop=False,
        check_replay=False,
        audit_log=io.StringIO(),  # Suppress audit output
    )

    @server.skill("analyze_data", constraints={"chunk_size": Range(10, 1000)})
    async def analyze_data(data_path: str, chunk_size: int):
        """
        Analyze data in chunks (streaming skill).

        This is a generator - yields results as they're computed.
        The A2A server automatically streams these via SSE.
        """
        # Simulate data analysis in chunks
        total_items = 100
        processed = 0

        for i in range(0, total_items, chunk_size):
            # Simulate processing time
            await asyncio.sleep(0.5)

            chunk_end = min(i + chunk_size, total_items)
            processed = chunk_end

            # Yield intermediate result
            yield {
                "processed": processed,
                "total": total_items,
                "percent": int((processed / total_items) * 100),
                "chunk_result": f"Analyzed items {i}-{chunk_end}",
            }

        # Final result
        return {
            "status": "complete",
            "total_processed": total_items,
            "summary": f"Analyzed {total_items} items in {total_items // chunk_size} chunks",
        }

    @server.skill("process_file", constraints={"path": Subpath("/tmp/data")})
    async def process_file(path: str):
        """
        Process a file with streaming progress updates.

        Regular async function (not generator) - returns final result only.
        """
        # Simulate file processing
        await asyncio.sleep(2)
        return {
            "status": "complete",
            "path": path,
            "bytes_processed": 1024 * 1024,  # 1 MB
        }

    return server


# =============================================================================
# Demo
# =============================================================================

async def run_demo():
    """Run the streaming demo."""

    header("A2A Streaming Demo")

    # Setup keys
    log("🔑 Generating cryptographic keys...")
    control_key = SigningKey.generate()
    worker_key = SigningKey.generate()
    orchestrator_key = SigningKey.generate()

    # Create server
    log("🚀 Starting Analysis Agent server...")
    server = create_analysis_server(
        signing_key=worker_key,
        trusted_issuers=[control_key.public_key, orchestrator_key.public_key],
        port=8000,
    )

    # Start server in background
    import uvicorn
    config = uvicorn.Config(
        server.app,
        host="127.0.0.1",
        port=8000,
        log_level="critical",
        lifespan="off",
    )
    uv_server = uvicorn.Server(config)
    server_task = asyncio.create_task(uv_server.serve())

    # Wait for server to start
    await asyncio.sleep(1)
    log("✅ Server running on http://localhost:8000\n")

    try:
        # Create warrant
        log("📜 Issuing warrant to Orchestrator...")
        orchestrator_warrant = (Warrant.mint_builder()
            .capability("analyze_data", chunk_size=Range(10, 1000))
            .capability("process_file", path=Subpath("/tmp/data"))
            .holder(orchestrator_key.public_key)
            .ttl(600)
            .mint(control_key))

        log(f"   Warrant ID: {orchestrator_warrant.id[:12]}...")
        log("   Tools: analyze_data, process_file\n")

        # Create client
        client = A2AClient("http://localhost:8000")

        # =================================================================
        # Demo 1: Streaming Analysis (Generator Skill)
        # =================================================================

        header("Demo 1: Streaming Analysis")
        log("📊 Starting data analysis with chunk_size=25")
        log("   The server will stream progress updates as it processes...\n")

        start_time = time.time()
        chunk_count = 0

        async for update in client.send_task_streaming(
            message="Analyze the dataset",
            warrant=orchestrator_warrant,
            skill="analyze_data",
            arguments={"data_path": "/data/dataset.csv", "chunk_size": 25},
            signing_key=orchestrator_key,
            stream_timeout=30.0,
        ):
            if update.type.value == "status":
                log(f"   Status: {update.status}", C.YELLOW)

            elif update.type.value == "message":
                # Intermediate chunk result
                chunk_count += 1
                import json
                chunk_data = json.loads(update.content) if isinstance(update.content, str) else update.content
                percent = chunk_data.get("percent", 0)
                processed = chunk_data.get("processed", 0)
                total = chunk_data.get("total", 0)

                # Progress bar
                bar_length = 30
                filled = int(bar_length * percent / 100)
                bar = "█" * filled + "░" * (bar_length - filled)

                log(f"   [{bar}] {percent}% ({processed}/{total})", C.GREEN)

            elif update.type.value == "complete":
                elapsed = time.time() - start_time
                log(f"\n✅ Analysis complete in {elapsed:.1f}s", C.GREEN)
                log(f"   Received {chunk_count} progress updates")
                if update.output:
                    import json
                    output = json.loads(update.output) if isinstance(update.output, str) else update.output
                    log(f"   Summary: {output.get('summary', 'N/A')}")

            elif update.type.value == "error":
                log(f"❌ Error: {update.content}", C.YELLOW)

        # =================================================================
        # Demo 2: Non-Streaming Task (Regular Function)
        # =================================================================

        header("Demo 2: Non-Streaming Task")
        log("📁 Processing file (non-streaming)...")
        log("   Regular task - single response when complete\n")

        result = await client.send_task(
            message="Process the input file",
            warrant=orchestrator_warrant,
            skill="process_file",
            arguments={"path": "/tmp/data/input.txt"},
            signing_key=orchestrator_key,
        )

        log(f"✅ File processed: {result.output}")

        # =================================================================
        # Demo 3: Streaming with Different Chunk Sizes
        # =================================================================

        header("Demo 3: Chunk Size Comparison")

        for chunk_size in [10, 50]:
            log(f"\n📊 Running with chunk_size={chunk_size}")

            chunk_count = 0
            async for update in client.send_task_streaming(
                message="Analyze dataset",
                warrant=orchestrator_warrant,
                skill="analyze_data",
                arguments={"data_path": "/data/dataset.csv", "chunk_size": chunk_size},
                signing_key=orchestrator_key,
                stream_timeout=30.0,
            ):
                if update.type.value == "message":
                    chunk_count += 1
                elif update.type.value == "complete":
                    log(f"   Completed with {chunk_count} chunks")

        # =================================================================
        # Demo 4: Stream Timeout (DoS Protection)
        # =================================================================

        header("Demo 4: Stream Timeout Protection")
        log("⏱️  Setting aggressive timeout (1 second)...")
        log("   This would trigger for slow servers (DoS protection)\n")

        try:
            async for update in client.send_task_streaming(
                message="Analyze dataset",
                warrant=orchestrator_warrant,
                skill="analyze_data",
                arguments={"data_path": "/data/dataset.csv", "chunk_size": 25},
                signing_key=orchestrator_key,
                stream_timeout=1.0,  # Very short timeout
            ):
                pass
        except TimeoutError as e:
            log(f"✅ Timeout triggered as expected: {e}", C.YELLOW)
            log("   This prevents slow-drip DoS attacks")

        # =================================================================
        # Summary
        # =================================================================

        header("Summary")
        log("✅ Streaming allows real-time progress updates")
        log("✅ Generators automatically stream via SSE")
        log("✅ Regular functions return single response")
        log("✅ Timeout protection prevents DoS attacks")
        log("\nKey takeaways:")
        log("  • Use streaming for long-running tasks")
        log("  • Client sees progress as it happens")
        log("  • Server-Sent Events (SSE) transport")
        log("  • stream_timeout prevents hung connections")

    finally:
        # Cleanup
        log("\n🧹 Shutting down server...")
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0.5)


async def main():
    """Entry point."""
    try:
        await run_demo()
    except KeyboardInterrupt:
        print("\n\n^C received")


if __name__ == "__main__":
    asyncio.run(main())
