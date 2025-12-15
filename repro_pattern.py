from tenuo import Warrant, Keypair, Pattern, Wildcard

def test_pattern_subset():
    kp = Keypair.generate()
    
    # Parent with Pattern("*")
    parent = Warrant.issue(
        tools=["test"],
        keypair=kp,
        constraints={"q": Pattern("*")},
        ttl_seconds=3600
    )
    
    # Child with Pattern("*competitor*")
    builder = parent.attenuate_builder()
    builder.with_constraint("q", Pattern("*competitor*"))
    
    try:
        child = builder.delegate_to(kp, kp)
        print("Pattern('*') -> Pattern('*competitor*'): Success")
    except Exception as e:
        print(f"Pattern('*') -> Pattern('*competitor*'): Failed: {e}")

def test_wildcard_subset():
    kp = Keypair.generate()
    
    # Parent with Wildcard()
    parent = Warrant.issue(
        tools=["test"],
        keypair=kp,
        constraints={"q": Wildcard()},
        ttl_seconds=3600
    )
    
    # Child with Pattern("*competitor*")
    builder = parent.attenuate_builder()
    builder.with_constraint("q", Pattern("*competitor*"))
    
    try:
        child = builder.delegate_to(kp, kp)
        print("Wildcard() -> Pattern('*competitor*'): Success")
    except Exception as e:
        print(f"Wildcard() -> Pattern('*competitor*'): Failed: {e}")

if __name__ == "__main__":
    test_pattern_subset()
    test_wildcard_subset()
