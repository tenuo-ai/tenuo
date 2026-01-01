
from tenuo import SigningKey, Warrant, Pattern, Exact, Range
from tenuo.constraints import Constraints

def test_full_warrant_lifecycle():
    """
    Test the full lifecycle of a warrant:
    1. Key generation
    2. Root warrant issuance
    3. Attenuation (delegation)
    4. Authorization (success/failure)
    5. Serialization
    """
    # 1. Generate keypairs
    control_keypair = SigningKey.generate()
    worker_keypair = SigningKey.generate()

    assert len(control_keypair.public_key_bytes()) == 32
    assert len(worker_keypair.public_key_bytes()) == 32

    # 2. Create a root warrant with constraints
    root_warrant = Warrant.mint(
        keypair=control_keypair,
        capabilities=Constraints.for_tool("manage_infrastructure", {
            "cluster": Pattern("staging-*"),
            "replicas": Range.max_value(15)
        }),
        ttl_seconds=3600,
        holder=control_keypair.public_key
    )

    assert root_warrant.tools == ["manage_infrastructure"]
    assert root_warrant.depth == 0
    assert not root_warrant.is_expired()

    # 3. Attenuate (delegate) the warrant to a worker
    # The signing_key must be the holder of the parent warrant
    worker_warrant = root_warrant.attenuate(
        capabilities=Constraints.for_tool("manage_infrastructure", {
            "cluster": Exact("staging-web"),
            "replicas": Range.max_value(10)
        }),
        signing_key=control_keypair,  # Control plane signs (they hold root)
        holder=worker_keypair.public_key  # Bound to worker
    )

    assert worker_warrant.tools == ["manage_infrastructure"]
    assert worker_warrant.depth == 1

    # 4. Test authorization

    # Helper to authorize with PoP
    def check_auth(warrant, tool, args, keypair):
        signature = warrant.sign(keypair, tool, args)
        return warrant.authorize(tool, args, bytes(signature))

    # Allowed: matches constraints
    args1 = {"cluster": "staging-web", "replicas": 5}
    assert check_auth(worker_warrant, "manage_infrastructure", args1, worker_keypair) is True

    # Denied: replicas too high
    args2 = {"cluster": "staging-web", "replicas": 20}
    assert check_auth(worker_warrant, "manage_infrastructure", args2, worker_keypair) is False

    # Denied: wrong cluster
    args3 = {"cluster": "production-web", "replicas": 5}
    assert check_auth(worker_warrant, "manage_infrastructure", args3, worker_keypair) is False

    # Denied: wrong keypair (PoP failure)
    wrong_keypair = SigningKey.generate()
    assert check_auth(worker_warrant, "manage_infrastructure", args1, wrong_keypair) is False

    # 5. Serialization
    warrant_base64 = worker_warrant.to_base64()
    assert isinstance(warrant_base64, str)
    assert len(warrant_base64) > 0

    # Deserialize
    deserialized = Warrant.from_base64(warrant_base64)
    assert deserialized.tools == worker_warrant.tools
    assert deserialized.id == worker_warrant.id
