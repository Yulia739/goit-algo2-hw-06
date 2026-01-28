from typing import Any, Dict, Iterable
import hashlib


class BloomFilter:
    """
    Простий Bloom filter:
    - size: кількість бітів
    - num_hashes: кількість хеш-функцій
    Пам'ять: bitarray на базі bytearray (мінімально просто і без сторонніх бібліотек).
    """

    def __init__(self, size: int, num_hashes: int) -> None:
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size має бути додатнім цілим числом")
        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes має бути додатнім цілим числом")

        self.size = size
        self.num_hashes = num_hashes
        self._bits = bytearray((size + 7) // 8)

    def _set_bit(self, idx: int) -> None:
        byte_i = idx // 8
        bit_i = idx % 8
        self._bits[byte_i] |= (1 << bit_i)

    def _get_bit(self, idx: int) -> int:
        byte_i = idx // 8
        bit_i = idx % 8
        return (self._bits[byte_i] >> bit_i) & 1

    def _hash_positions(self, item: str):
        """
        Генеруємо num_hashes позицій у [0, size).
        Використаємо double hashing:
          h1 = sha256(item)
          h2 = md5(item)
          pos_i = (h1 + i*h2) % size
        Це стандартний підхід, щоб не рахувати багато різних хешів.
        """
        b = item.encode("utf-8", errors="replace")
        h1 = int.from_bytes(hashlib.sha256(b).digest(), "big")
        h2 = int.from_bytes(hashlib.md5(b).digest(), "big") or 1

        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.size

    def add(self, item: str) -> None:
        if not isinstance(item, str):
            raise TypeError("BloomFilter.add очікує рядок (str)")
        for pos in self._hash_positions(item):
            self._set_bit(pos)

    def contains(self, item: str) -> bool:
        if not isinstance(item, str):
            raise TypeError("BloomFilter.contains очікує рядок (str)")
        return all(self._get_bit(pos) for pos in self._hash_positions(item))


def check_password_uniqueness(
    bloom: BloomFilter,
    new_passwords: Iterable[Any],
    add_unique_to_filter: bool = False
) -> Dict[str, str]:
    results: Dict[str, str] = {}

    for p in new_passwords:
        key = p if isinstance(p, str) else str(p)

        if p is None or not isinstance(p, str) or p.strip() == "":
            results[key] = "некоректний"
            continue

        if bloom.contains(p):
            results[p] = "вже використаний"
        else:
            results[p] = "унікальний"
            if add_unique_to_filter:
                bloom.add(p)

    return results



if __name__ == "__main__":
    bloom = BloomFilter(size=1000, num_hashes=3)

    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")
