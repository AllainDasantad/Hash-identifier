from hash_identifier.detector import identify_hash


def main():
    print("I used Arch btw")
    print("       HASH IDENTIFIER")
    print("I did everything by myself")

    hash_value = input("Enter hash: ").strip()

    results = identify_hash(hash_value)

    if not results:
        print("\nNo recognized hash formats found.")
        return

    print("\nPossible matches:")

    for result in results:
        print(f"\nAlgorithm : {result.algorithm}")
        print(f"Confidence: {result.confidence}")
        print(f"Reason    : {result.reason}")


if __name__ == "__main__":
    main()
