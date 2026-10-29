import math
import gzip
import functools
from typing import Tuple, List, Dict, Callable, Optional
from collections import Counter

import numpy as np
from scipy.special import erfc, ndtr
from cryptography.fernet import Fernet

from .config import AVALANCHE_TRIALS


@functools.lru_cache(maxsize=64)
def _unpackbits_cached(data_bytes: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data_bytes, dtype=np.uint8))


def _norm_cdf(x: float) -> float:
    return float(ndtr(x))


class CryptoScientificLibrary:
    @staticmethod
    def get_shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

    @staticmethod
    def nist_monobit_test(data: bytes) -> Tuple[float, float]:
        if not data:
            return 0.0, 0.0
        bits = _unpackbits_cached(data)
        n = len(bits)
        if n == 0:
            return 0.0, 0.0
        s_obs = abs(np.sum(2 * bits - 1))
        s_obs_norm = s_obs / math.sqrt(n)
        p_value = float(erfc(s_obs_norm / math.sqrt(2)))
        return float(s_obs / n), p_value

    @staticmethod
    def nist_block_frequency_test(data: bytes, block_size: int = 8) -> Tuple[float, float]:
        if not data:
            return 0.0, 0.0
        bits = _unpackbits_cached(data)
        n = len(bits)
        num_blocks = n // block_size
        if num_blocks == 0:
            return 0.0, 0.0
        pi_sum = 0.0
        for i in range(num_blocks):
            block = bits[i * block_size: (i + 1) * block_size]
            pi = np.sum(block) / block_size
            pi_sum += (pi - 0.5) ** 2
        chi_sq = 4 * block_size * pi_sum
        p_value = float(erfc(math.sqrt(chi_sq / 2)))
        return float(chi_sq), p_value

    @staticmethod
    def nist_runs_test(data: bytes) -> Tuple[float, float]:
        if not data:
            return 0.0, 0.0
        bits = _unpackbits_cached(data)
        n = len(bits)
        if n < 2:
            return 1.0, 0.0
        pi = np.sum(bits) / n
        if abs(pi - 0.5) >= (2 / math.sqrt(n)):
            return 0.0, 0.0
        runs = int(np.sum(bits[1:] != bits[:-1])) + 1
        num_expected = 2 * n * pi * (1 - pi) + 1
        denom = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        if denom == 0:
            return float(runs), 0.0
        p_value = float(erfc(abs(runs - num_expected) / denom))
        return float(runs / num_expected), p_value

    @staticmethod
    def nist_spectral_fft_test(data: bytes) -> Tuple[float, float]:
        if not data:
            return 0.0, 0.0
        bits = _unpackbits_cached(data)
        n = len(bits)
        if n < 10:
            return 0.0, 0.0
        x = 2 * bits - 1
        s = np.fft.fft(x)
        m = np.abs(s[:n // 2])
        t = math.sqrt(math.log(1 / 0.05) * n)
        n0 = 0.95 * (n / 2)
        n1 = float(np.sum(m < t))
        d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4)
        p_value = float(erfc(abs(d) / math.sqrt(2)))
        return float(d), p_value

    @staticmethod
    def nist_cumulative_sums_test(data: bytes) -> Tuple[float, float]:
        """NIST Cumulative Sums (Cusum) Test — forward direction."""
        if not data:
            return 0.0, 0.0
        bits = _unpackbits_cached(data)
        n = len(bits)
        if n < 2:
            return 0.0, 0.0
        S = np.cumsum(2 * bits.astype(np.float64) - 1)
        z = float(np.max(np.abs(S))) / math.sqrt(n)
        sum_val = 0.0
        max_k = int(n / z) + 1 if z > 0 else 1
        for k in range(-max_k, max_k + 1):
            term1 = _norm_cdf(((4 * k + 1) * z) / math.sqrt(n))
            term2 = _norm_cdf(((4 * k - 1) * z) / math.sqrt(n))
            sum_val += term1 - term2
        p_value = float(1.0 - sum_val)
        p_value = max(0.0, min(1.0, p_value))
        return z, p_value

    @staticmethod
    def nist_serial_test(data: bytes, m: int = 2) -> Tuple[float, float]:
        """NIST Serial Test — tests uniformity of overlapping m-bit patterns."""
        if not data:
            return 0.0, 0.0
        bits = _unpackbits_cached(data)
        n = len(bits)
        if n < m + 1:
            return 0.0, 0.0

        def psi_sq(mm: int) -> float:
            if mm == 0:
                return 0.0
            nn = n
            ext = np.concatenate([bits, bits[:mm - 1]])
            pattern_counts: Dict = {}
            for i in range(nn):
                pattern = tuple(ext[i:i + mm])
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
            total = float(nn)
            return (2 ** mm / total) * sum(c * c for c in pattern_counts.values()) - total

        psi_m = psi_sq(m)
        psi_m1 = psi_sq(m - 1)
        psi_m2 = psi_sq(m - 2) if m >= 2 else 0.0
        delta1 = psi_m - psi_m1
        delta2 = psi_m - 2 * psi_m1 + psi_m2
        p1 = float(erfc(abs(delta1) / (2 * math.sqrt(2))))
        p2 = float(erfc(abs(delta2) / (2 * math.sqrt(2))))
        return p1, p2

    @staticmethod
    def nist_approximate_entropy_test(data: bytes, m: int = 2) -> Tuple[float, float]:
        """NIST Approximate Entropy Test."""
        if not data:
            return 0.0, 0.0
        bits = _unpackbits_cached(data)
        n = len(bits)
        if n < m + 2:
            return 0.0, 0.0

        def phi(mm: int) -> float:
            ext = np.concatenate([bits, bits[:mm]])
            counts: Dict = {}
            for i in range(n):
                pattern = tuple(ext[i:i + mm])
                counts[pattern] = counts.get(pattern, 0) + 1
            total = float(n)
            return sum((c / total) * math.log(c / total) for c in counts.values())

        phi_m = phi(m)
        phi_m1 = phi(m + 1)
        ap_en = phi_m - phi_m1
        chi_sq = 2.0 * n * (math.log(2) - ap_en)
        p_value = float(erfc(math.sqrt(chi_sq / 2)))
        return float(ap_en), p_value

    @staticmethod
    def byte_uniformity_score(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        expected = length / 256.0
        if expected == 0:
            return 0.0
        chi2 = sum((c - expected) ** 2 / expected for c in counts.values())
        score = 1.0 / (1.0 + chi2 / max(len(counts), 1))
        return max(0.0, min(1.0, float(score)))

    @staticmethod
    def byte_chi_square(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        expected = length / 256.0
        if expected == 0:
            return 0.0
        return sum((c - expected) ** 2 / expected for c in counts.values())

    @staticmethod
    def autocorrelation(data: bytes, lag: int = 1) -> float:
        """Autocorrelation coefficient at given lag."""
        if not data or len(data) < lag + 2:
            return 0.0
        arr = np.frombuffer(data, dtype=np.uint8).astype(np.float64)
        n = len(arr)
        mean = np.mean(arr)
        var = np.sum((arr - mean) ** 2)
        if var == 0:
            return 0.0
        ac = np.sum((arr[:n - lag] - mean) * (arr[lag:] - mean)) / var
        return float(ac)

    @staticmethod
    def compression_ratio(data: bytes) -> float:
        """Ratio of gzip-compressed size to original size (< 1.0 = compressible)."""
        if not data:
            return 1.0
        compressed = gzip.compress(data)
        return len(compressed) / max(len(data), 1)

    @staticmethod
    def diffusion_score(c1: bytes, c2: bytes) -> float:
        if not c1 or not c2:
            return 0.0
        b1 = _unpackbits_cached(c1)
        b2 = _unpackbits_cached(c2)
        length = min(len(b1), len(b2))
        if length == 0:
            return 0.0
        return float(np.mean(b1[:length] != b2[:length]))

    @staticmethod
    def get_avalanche_score(
        msg: str,
        key: bytes,
        trials: int = AVALANCHE_TRIALS,
        encrypt_fn: Optional[Callable] = None,
    ) -> float:
        try:
            if not msg:
                msg = "A"
            if encrypt_fn is None:
                f = Fernet(key)
                encrypt_fn = f.encrypt
            diffs: List[float] = []
            for _ in range(trials):
                c1 = encrypt_fn(msg.encode())
                mb = bytearray(msg.encode())
                bi = np.random.randint(0, len(mb))
                bb = np.random.randint(0, 8)
                mb[bi] ^= (1 << bb)
                c2 = encrypt_fn(bytes(mb))
                b1 = _unpackbits_cached(c1)
                b2 = _unpackbits_cached(c2)
                length = min(len(b1), len(b2))
                if length > 0:
                    diffs.append(float(np.mean(b1[:length] != b2[:length])))
            return float(np.mean(diffs) * 100.0) if diffs else 0.0
        except Exception:
            return 0.0

    @staticmethod
    def normalize_metrics(h, sac, uni, mono, runs, diff):
        h_norm = min(h / 8.0, 1.0)
        sac_norm = max(0.0, min(1.0, 1.0 - abs(sac - 50.0) / 50.0))
        uni_norm = max(0.0, min(1.0, uni))
        mono_norm = max(0.0, min(1.0, 1.0 - mono))
        runs_norm = max(0.0, min(1.0, 1.0 - abs(runs - 1.0)))
        diff_norm = max(0.0, min(1.0, 1.0 - abs(diff - 0.5) / 0.5))
        return h_norm, sac_norm, uni_norm, mono_norm, runs_norm, diff_norm

    @staticmethod
    def weighted_security_index(hn, sacn, unin, monon, runsn, diffn, weights: Dict[str, float]) -> float:
        w_sum = sum(weights.values())
        if w_sum <= 0:
            w_norm = {k: 1.0 / 6.0 for k in ["h", "sac", "uni", "mono", "runs", "diff"]}
        else:
            w_norm = {k: v / w_sum for k, v in weights.items()}
        score = (
            hn * w_norm["h"] + sacn * w_norm["sac"] +
            unin * w_norm["uni"] + monon * w_norm["mono"] +
            runsn * w_norm["runs"] + diffn * w_norm["diff"]
        )
        return float(score)

    @staticmethod
    def extract_full_features(data: bytes, msg: str, key: bytes,
                               encrypt_fn: Optional[Callable] = None) -> np.ndarray:
        """Extract 16 features for ML classification."""
        feats = []

        # 1. Shannon entropy
        feats.append(CryptoScientificLibrary.get_shannon_entropy(data))

        # 2. SAC avalanche score
        feats.append(CryptoScientificLibrary.get_avalanche_score(msg, key, encrypt_fn=encrypt_fn))

        # 3. Byte uniformity
        feats.append(CryptoScientificLibrary.byte_uniformity_score(data))

        # 4-5. Monobit
        mono_stat, mono_p = CryptoScientificLibrary.nist_monobit_test(data)
        feats.append(mono_stat)
        feats.append(mono_p)

        # 6-7. Block frequency
        blk_stat, blk_p = CryptoScientificLibrary.nist_block_frequency_test(data)
        feats.append(blk_stat)
        feats.append(blk_p)

        # 8-9. Runs
        runs_stat, runs_p = CryptoScientificLibrary.nist_runs_test(data)
        feats.append(runs_stat)
        feats.append(runs_p)

        # 10-11. FFT
        fft_stat, fft_p = CryptoScientificLibrary.nist_spectral_fft_test(data)
        feats.append(fft_stat)
        feats.append(fft_p)

        # 12. Diffusion (requires modified ciphertext)
        msg_bytes = bytearray(msg.encode() if msg else b"A")
        msg_bytes[0] ^= 1
        if encrypt_fn is None:
            f = Fernet(key)
            c2 = f.encrypt(bytes(msg_bytes))
        else:
            c2 = encrypt_fn(bytes(msg_bytes))
        feats.append(CryptoScientificLibrary.diffusion_score(data, c2))

        # 13. Cumulative sums (forward)
        cum_z, cum_p = CryptoScientificLibrary.nist_cumulative_sums_test(data)
        feats.append(cum_p)

        # 14. Serial test
        ser_p1, ser_p2 = CryptoScientificLibrary.nist_serial_test(data)
        feats.append(ser_p1)
        feats.append(ser_p2)

        # 15. Approximate entropy
        ap_en, ap_p = CryptoScientificLibrary.nist_approximate_entropy_test(data)
        feats.append(ap_p)

        # 16. Chi-square byte statistic
        feats.append(CryptoScientificLibrary.byte_chi_square(data))

        # 17. Autocorrelation lag-1
        feats.append(CryptoScientificLibrary.autocorrelation(data, lag=1))

        # 18. Compression ratio
        feats.append(CryptoScientificLibrary.compression_ratio(data))

        return np.array(feats, dtype=np.float64)

    @staticmethod
    def run_full_suite(
        data: bytes,
        msg: str,
        key: bytes,
        encrypt_fn: Optional[Callable] = None,
    ) -> Dict:
        h = CryptoScientificLibrary.get_shannon_entropy(data)
        sac = CryptoScientificLibrary.get_avalanche_score(msg, key, encrypt_fn=encrypt_fn)
        uni = CryptoScientificLibrary.byte_uniformity_score(data)
        mono_imb, mono_p = CryptoScientificLibrary.nist_monobit_test(data)
        block_chi, block_p = CryptoScientificLibrary.nist_block_frequency_test(data)
        runs_r, runs_p = CryptoScientificLibrary.nist_runs_test(data)
        fft_d, fft_p = CryptoScientificLibrary.nist_spectral_fft_test(data)
        _, cum_p = CryptoScientificLibrary.nist_cumulative_sums_test(data)
        ser_p1, ser_p2 = CryptoScientificLibrary.nist_serial_test(data)
        _, ap_p = CryptoScientificLibrary.nist_approximate_entropy_test(data)

        msg_bytes = bytearray(msg.encode() if msg else b"A")
        msg_bytes[0] ^= 1
        if encrypt_fn is None:
            f = Fernet(key)
            c2 = f.encrypt(bytes(msg_bytes))
        else:
            c2 = encrypt_fn(bytes(msg_bytes))
        diff = CryptoScientificLibrary.diffusion_score(data, c2)

        return {
            "h": h, "sac": sac, "uni": uni,
            "mono": mono_imb, "mono_p": mono_p,
            "block_p": block_p, "runs": runs_r, "runs_p": runs_p,
            "fft_d": fft_d, "fft_p": fft_p, "diff": diff,
            "cum_p": cum_p, "ser_p1": ser_p1, "ser_p2": ser_p2, "ap_p": ap_p,
            "chi2": CryptoScientificLibrary.byte_chi_square(data),
            "autocorr": CryptoScientificLibrary.autocorrelation(data),
            "compress": CryptoScientificLibrary.compression_ratio(data),
        }

    @staticmethod
    def compute_security_index(metrics: Dict, weights: Dict[str, float]) -> float:
        hn, sacn, unin, monon, runsn, diffn = CryptoScientificLibrary.normalize_metrics(
            metrics["h"], metrics["sac"], metrics["uni"],
            metrics["mono"], metrics["runs"], metrics["diff"]
        )
        return CryptoScientificLibrary.weighted_security_index(
            hn, sacn, unin, monon, runsn, diffn, weights
        )

    # ------------------------------------------------------------------
    # Scientific visualization helpers (data for Plotly charts)
    # ------------------------------------------------------------------

    @staticmethod
    def bitstream_matrix(data: bytes, width: int = 32) -> np.ndarray:
        """Reshape bytes into a 2D matrix for heatmap (rows x width)."""
        if not data:
            return np.zeros((1, width), dtype=np.uint8)
        arr = np.frombuffer(data, dtype=np.uint8)
        n = len(arr)
        rows = max(1, (n + width - 1) // width)
        padded = np.zeros(rows * width, dtype=np.uint8)
        padded[:n] = arr
        return padded.reshape(rows, width)

    @staticmethod
    def rolling_entropy(data: bytes, window: int = 64) -> Tuple[np.ndarray, np.ndarray]:
        """Shannon entropy over sliding windows. Returns (positions, entropy_values)."""
        if not data or window < 2:
            return np.array([0]), np.array([0.0])
        arr = np.frombuffer(data, dtype=np.uint8)
        n = len(arr)
        if n < window:
            return np.array([0]), np.array([CryptoScientificLibrary.get_shannon_entropy(data)])
        positions, values = [], []
        for i in range(0, n - window + 1, max(1, window // 4)):
            chunk = bytes(arr[i:i + window])
            positions.append(i + window // 2)
            values.append(CryptoScientificLibrary.get_shannon_entropy(chunk))
        return np.array(positions), np.array(values)

    @staticmethod
    def runs_length_histogram(data: bytes) -> Dict[str, np.ndarray]:
        """Histogram of run lengths for bit 0 and bit 1."""
        if not data:
            return {"lengths_0": np.array([]), "counts_0": np.array([]),
                    "lengths_1": np.array([]), "counts_1": np.array([])}
        bits = _unpackbits_cached(data)
        if len(bits) < 2:
            return {"lengths_0": np.array([]), "counts_0": np.array([]),
                    "lengths_1": np.array([]), "counts_1": np.array([])}
        runs_0, runs_1 = [], []
        current = int(bits[0])
        length = 1
        for b in bits[1:]:
            if int(b) == current:
                length += 1
            else:
                (runs_1 if current == 1 else runs_0).append(length)
                current = int(b)
                length = 1
        (runs_1 if current == 1 else runs_0).append(length)

        def _hist(runs):
            if not runs:
                return np.array([]), np.array([])
            c = Counter(runs)
            keys = sorted(c.keys())
            return np.array(keys), np.array([c[k] for k in keys])

        l0, c0 = _hist(runs_0)
        l1, c1 = _hist(runs_1)
        return {"lengths_0": l0, "counts_0": c0, "lengths_1": l1, "counts_1": c1}

    @staticmethod
    def fft_spectrum_data(data: bytes) -> Dict[str, np.ndarray]:
        """Power spectrum for FFT plot + NIST threshold."""
        if not data:
            return {"freqs": np.array([]), "magnitude": np.array([]), "threshold": 0.0}
        bits = _unpackbits_cached(data)
        n = len(bits)
        if n < 10:
            return {"freqs": np.array([]), "magnitude": np.array([]), "threshold": 0.0}
        x = 2 * bits.astype(np.float64) - 1
        s = np.fft.fft(x)
        m = np.abs(s[: n // 2])
        freqs = np.arange(len(m))
        t = math.sqrt(math.log(1 / 0.05) * n)
        return {"freqs": freqs, "magnitude": m, "threshold": float(t)}

    @staticmethod
    def avalanche_detail(
        msg: str,
        key: bytes,
        encrypt_fn: Optional[Callable] = None,
        trials: int = 8,
    ) -> Dict:
        """
        Per-trial avalanche: Hamming distance fraction after flipping 1 bit.
        Returns trials list, mean, std, and bit-difference vector of last trial.
        """
        try:
            if not msg:
                msg = "A"
            if encrypt_fn is None:
                f = Fernet(key)
                encrypt_fn = f.encrypt
            diffs = []
            last_bitdiff = None
            for _ in range(trials):
                c1 = encrypt_fn(msg.encode())
                mb = bytearray(msg.encode())
                bi = int(np.random.randint(0, len(mb)))
                bb = int(np.random.randint(0, 8))
                mb[bi] ^= (1 << bb)
                c2 = encrypt_fn(bytes(mb))
                b1 = _unpackbits_cached(c1)
                b2 = _unpackbits_cached(c2)
                length = min(len(b1), len(b2))
                if length > 0:
                    bitdiff = (b1[:length] != b2[:length]).astype(np.float64)
                    frac = float(np.mean(bitdiff))
                    diffs.append(frac * 100.0)
                    last_bitdiff = bitdiff
            if not diffs:
                return {"trials": [], "mean": 0.0, "std": 0.0, "bitdiff": np.array([])}
            return {
                "trials": diffs,
                "mean": float(np.mean(diffs)),
                "std": float(np.std(diffs)),
                "bitdiff": last_bitdiff if last_bitdiff is not None else np.array([]),
            }
        except Exception:
            return {"trials": [], "mean": 0.0, "std": 0.0, "bitdiff": np.array([])}

    @staticmethod
    def byte_histogram(data: bytes) -> Tuple[np.ndarray, np.ndarray]:
        """Byte value histogram (0-255 counts)."""
        if not data:
            return np.arange(256), np.zeros(256)
        arr = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        return np.arange(256), counts.astype(np.float64)

    @staticmethod
    def pvalue_radar_data(metrics: Dict) -> Dict[str, float]:
        """Collect all NIST + auxiliary p-values for radar chart."""
        return {
            "Monobit": float(metrics.get("mono_p", 0.5)),
            "Block Freq": float(metrics.get("block_p", 0.5)),
            "Runs": float(metrics.get("runs_p", 0.5)),
            "FFT": float(metrics.get("fft_p", 0.5)),
            "Cusum": float(metrics.get("cum_p", 0.5)),
            "Serial p1": float(metrics.get("ser_p1", 0.5)),
            "Serial p2": float(metrics.get("ser_p2", 0.5)),
            "Approx Ent": float(metrics.get("ap_p", 0.5)),
        }
