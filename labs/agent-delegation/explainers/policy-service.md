# What a policy service costs

Both stage 4 fixes build the same thing: a central component that is told about every task before it starts and consulted on every call while it runs. Look at the round-trip column in the trace. Its availability now gates every tool call, and it holds state for every open task. It also has no idea what any caller was granted, which is what stage 5 exploits.
