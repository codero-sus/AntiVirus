"""A perfectly ordinary Python script (harmless demo)."""


def add(a, b):
    return a + b


def main():
    total = 0
    for i in range(1, 11):
        total += i
    print("sum of 1..10 =", add(total, 0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
