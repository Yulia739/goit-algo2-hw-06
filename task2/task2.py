import time
import math
import hashlib
import ipaddress
from pathlib import Path
from typing import Iterable, Optional, Tuple, Dict
import re
import ipaddress
from typing import Optional

_IP_CANDIDATE_RE = re.compile(r"(?<![\w:])([0-9a-fA-F:.]{3,})(?![\w:])")

def extract_ip(line: str) -> Optional[str]:
    """
    Шукає першу валідну IP (IPv4/IPv6) будь-де в рядку.
    Ігнорує некоректні рядки.
    """
    if not line:
        return None

    for m in _IP_CANDIDATE_RE.finditer(line):
        token = m.group(1).strip("[](){}<>,;\"'")
        try:
            ipaddress.ip_address(token)
            return token
        except ValueError:
            continue

    return None


def load_ips_stream(log_path: str) -> Iterable[str]:
    """
    Потокове читання IP з файлу. Некоректні рядки ігноруються.
    Працює на великих файлах: не завантажує все в пам'ять.
    """
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ip = extract_ip(line.strip())
            if ip is not None:
                yield ip


def exact_unique_count(ips: Iterable[str]) -> int:
    """
    Точний підрахунок унікальних через set (пам'ять O(n)).
    """
    s = set()
    for ip in ips:
        s.add(ip)
    return len(s)


class HyperLogLog:
    """
    Простий HyperLogLog (HLL) для оцінки кількості унікальних.
    - p: кількість бітів для індексу регістру (m = 2^p регістрів)
    Типові p: 10..16 (чим більше p, тим точніше і більше пам'яті)
    """
    def __init__(self, p: int = 14):
        if not isinstance(p, int) or p < 4 or p > 20:
            raise ValueError("p має бути int у межах приблизно 4..20")
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m

        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1.0 + 1.079 / self.m)

    @staticmethod
    def _hash64(x: str) -> int:
        d = hashlib.blake2b(x.encode("utf-8", errors="replace"), digest_size=8).digest()
        return int.from_bytes(d, "big", signed=False)

    @staticmethod
    def _clz(w: int, bits: int) -> int:
        if w == 0:
            return bits
        return bits - w.bit_length()

    def add(self, item: str) -> None:
        x = self._hash64(item)
        idx = x >> (64 - self.p)
        w = x & ((1 << (64 - self.p)) - 1)
        rho = self._clz(w, 64 - self.p) + 1
        if rho > self.registers[idx]:
            self.registers[idx] = rho

    def estimate(self) -> float:
        m = self.m
        inv_sum = 0.0
        zeros = 0
        for r in self.registers:
            inv_sum += 2.0 ** (-r)
            if r == 0:
                zeros += 1

        raw = self.alpha * (m * m) / inv_sum

        if raw <= 2.5 * m and zeros > 0:
            return m * math.log(m / zeros)

        two64 = 2.0 ** 64
        if raw > (two64 / 30.0):
            return -two64 * math.log(1.0 - raw / two64)

        return raw


def hll_unique_count(ips: Iterable[str], p: int = 14) -> float:
    hll = HyperLogLog(p=p)
    for ip in ips:
        hll.add(ip)
    return hll.estimate()


def benchmark(log_path: str, p: int = 14) -> Dict[str, float]:
    t0 = time.perf_counter()
    exact = exact_unique_count(load_ips_stream(log_path))
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    approx = hll_unique_count(load_ips_stream(log_path), p=p)
    t3 = time.perf_counter()

    return {
        "exact_count": float(exact),
        "exact_time_s": t1 - t0,
        "hll_count": float(approx),
        "hll_time_s": t3 - t2,
    }


def print_results_table(res: Dict[str, float]) -> None:
    print("Результати порівняння:")
    header = f"{'':28} {'Точний підрахунок':>16} {'HyperLogLog':>12}"
    print(header)

    print(f"{'Унікальні елементи':28} {res['exact_count']:16.1f} {res['hll_count']:12.2f}")

    print(f"{'Час виконання (сек.)':28} {res['exact_time_s']:16.2f} {res['hll_time_s']:12.2f}")

    err = abs(res["hll_count"] - res["exact_count"]) / res["exact_count"] * 100 if res["exact_count"] else 0.0
    print(f"{'Похибка (%)':28} {'-':>16} {err:12.2f}")




if __name__ == "__main__":
    LOG_PATH = str(Path("task2") / "lms-stage-access.log")

    res = benchmark(LOG_PATH, p=14)
    print_results_table(res)
