def test_phase1_contract_documented():
    required = [
        "PROJECT_CONTEXT.md",
        "README.md",
        "README.txt",
        "docker-compose.yml",
        "deploy/install.sh",
        "docs/RADIUS_TESTING.md",
    ]
    for path in required:
        with open(path, "r", encoding="utf-8") as handle:
            assert handle.read()
