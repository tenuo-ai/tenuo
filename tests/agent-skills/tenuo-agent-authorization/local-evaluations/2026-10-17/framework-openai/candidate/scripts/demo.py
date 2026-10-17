"""Measured scripted calls and fake effect counts only."""
import asyncio
from agents.exceptions import UserError
import agent_app

async def main():
    print('Task warrant: refund_order(order_id="123", 1<=amount_cents<=50000)')
    for amount in [20000, 490000]:
        agent_app.effects.clear()
        try:
            await agent_app.run_agent([{"order_id": "123", "amount_cents": amount}])
            print(f"Allowed: ${amount / 100:.2f}; effects={len(agent_app.effects)}")
        except UserError as exc:
            print(f"Denied: ${amount / 100:.2f}; effects={len(agent_app.effects)}; {exc}")

asyncio.run(main())
