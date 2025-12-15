from tenuo import Warrant, Keypair, Pattern

def test_pattern_matching():
    kp = Keypair.generate()
    
    warrant = Warrant.issue(
        tools=["search"],
        keypair=kp,
        constraints={"query": Pattern("*competitor*")},
        ttl_seconds=3600
    )
    
    args = {"query": "competitor analysis"}
    if warrant.authorize("search", args):
        print("Match: Success")
    else:
        print("Match: Failed")

if __name__ == "__main__":
    test_pattern_matching()
