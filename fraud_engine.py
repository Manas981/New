"""Fraud feature engine for transaction-level risk scoring.

Implements the exact formulas requested for:
1) Spending deviation score
2) Velocity score
3) IP-based geo anomaly score
4) Final fraud risk score

This module maintains per-user historical state in memory for demonstration.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import asin, cos, exp, radians, sin, sqrt
from statistics import mean, pstdev
from typing import Dict, List, Optional, Tuple

try:
    import maxminddb  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    maxminddb = None


EPSILON = 1e-9
EARTH_RADIUS_KM = 6371.0


@dataclass
class UserState:
    """Per-user state needed for rolling fraud features."""

    # Historical amounts for rolling mean/std.
    amounts: List[float] = field(default_factory=list)

    # Historical timestamps for transaction frequency and hourly history.
    timestamps: List[datetime] = field(default_factory=list)

    # Last known network identity and time.
    last_lat: Optional[float] = None
    last_lon: Optional[float] = None
    last_asn: Optional[str] = None
    last_timestamp: Optional[datetime] = None

    # Historical geo movement distances (km) for geo std.
    geo_distances: List[float] = field(default_factory=list)


class FraudFeatureEngine:
    """In-memory fraud feature engine with optional MaxMind GeoLite2 support."""

    def __init__(self, geolite2_city_db_path: Optional[str] = None, geolite2_asn_db_path: Optional[str] = None):
        self.user_state: Dict[str, UserState] = defaultdict(UserState)

        self.city_reader = None
        self.asn_reader = None

        if geolite2_city_db_path and maxminddb:
            self.city_reader = maxminddb.open_database(geolite2_city_db_path)
        if geolite2_asn_db_path and maxminddb:
            self.asn_reader = maxminddb.open_database(geolite2_asn_db_path)

        # Deterministic fallback map for demo when MaxMind DBs are unavailable.
        self.fallback_geo = {
            "8.8.8.8": (37.386, -122.0838, "AS15169"),
            "1.1.1.1": (-33.8688, 151.2093, "AS13335"),
            "142.250.183.46": (40.7128, -74.0060, "AS15169"),
            "52.95.110.1": (28.6139, 77.2090, "AS16509"),
            "185.199.108.153": (51.5074, -0.1278, "AS54113"),
        }

    @staticmethod
    def _sigmoid(x: float) -> float:
        """Normalize score with logistic function: 1 / (1 + exp(-x))."""
        return 1.0 / (1.0 + exp(-x))

    @staticmethod
    def _parse_iso(ts: str) -> datetime:
        """Parse ISO timestamp into datetime."""
        return datetime.fromisoformat(ts)

    @staticmethod
    def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Haversine distance in kilometers.

        distance_km = 2 * R * asin(
            sqrt(
                sin²((lat2 - lat1)/2) +
                cos(lat1) * cos(lat2) * sin²((lon2 - lon1)/2)
            )
        )
        """
        d_lat = radians(lat2 - lat1)
        d_lon = radians(lon2 - lon1)
        r_lat1 = radians(lat1)
        r_lat2 = radians(lat2)

        a = sin(d_lat / 2) ** 2 + cos(r_lat1) * cos(r_lat2) * sin(d_lon / 2) ** 2
        return 2 * EARTH_RADIUS_KM * asin(sqrt(a))

    def _lookup_ip_geo(self, ip_address: str) -> Tuple[float, float, str]:
        """Resolve IP to (lat, lon, ASN).

        Uses GeoLite2 readers if configured; otherwise uses deterministic fallback.
        """
        if self.city_reader and self.asn_reader:
            city_data = self.city_reader.get(ip_address) or {}
            asn_data = self.asn_reader.get(ip_address) or {}

            lat = city_data.get("location", {}).get("latitude")
            lon = city_data.get("location", {}).get("longitude")
            asn_org = asn_data.get("autonomous_system_organization") or asn_data.get("autonomous_system_number")

            if lat is not None and lon is not None and asn_org is not None:
                return float(lat), float(lon), str(asn_org)

        if ip_address in self.fallback_geo:
            return self.fallback_geo[ip_address]

        # Stable default for unknown IPs in demo mode.
        return 0.0, 0.0, "ASN_UNKNOWN"

    @staticmethod
    def _hourly_counts(timestamps: List[datetime]) -> List[int]:
        """Build historical per-hour transaction count series from timestamps."""
        if not timestamps:
            return []
        c = Counter(ts.replace(minute=0, second=0, microsecond=0) for ts in timestamps)
        return list(c.values())

    def compute_fraud_features(self, transaction: Dict[str, object]) -> Dict[str, float]:
        """Compute fraud features and update user state.

        Input transaction schema:
          - transaction_id: str
          - user_id: str
          - timestamp: datetime ISO string
          - amount: float
          - ip_address: str
          - device_hash: str

        Returns:
          {
              'spending_score': float,
              'velocity_score': float,
              'geo_score': float,
              'fraud_risk_score': float
          }
        """
        user_id = str(transaction["user_id"])
        ts = self._parse_iso(str(transaction["timestamp"]))
        amount = float(transaction["amount"])
        ip_address = str(transaction["ip_address"])

        state = self.user_state[user_id]

        # ----------------------------------------
        # 1) SPENDING DEVIATION SCORE
        # ----------------------------------------
        # μ_u = rolling mean of historical transaction amounts
        # σ_u = rolling std deviation of historical amounts
        historical_amounts = state.amounts
        if historical_amounts:
            mu_u = mean(historical_amounts)
            sigma_u = pstdev(historical_amounts) if len(historical_amounts) > 1 else 0.0
        else:
            mu_u = amount
            sigma_u = 0.0

        # S_spend = |A_t − μ_u| / (σ_u + ε)
        s_spend = abs(amount - mu_u) / (sigma_u + EPSILON)

        # S_spend_norm = 1 / (1 + exp(-S_spend))
        s_spend_norm = self._sigmoid(s_spend)

        # ----------------------------------------
        # 2) VELOCITY SCORE
        # ----------------------------------------
        # N_w = number of transactions in the last 1 hour
        one_hour_ago = ts - timedelta(hours=1)
        n_w = sum(1 for hts in state.timestamps if one_hour_ago <= hts <= ts) + 1

        # λ_u = historical average transactions per hour
        # σ_λ = std deviation of hourly frequency
        hourly_counts = self._hourly_counts(state.timestamps)
        if hourly_counts:
            lambda_u = mean(hourly_counts)
            sigma_lambda = pstdev(hourly_counts) if len(hourly_counts) > 1 else 0.0
        else:
            lambda_u = 0.0
            sigma_lambda = 0.0

        # S_velocity = (N_w − λ_u) / (σ_λ + ε)
        s_velocity = (n_w - lambda_u) / (sigma_lambda + EPSILON)

        # S_velocity_norm = 1 / (1 + exp(-S_velocity))
        s_velocity_norm = self._sigmoid(s_velocity)

        # ----------------------------------------
        # 3) IP-BASED GEO ANOMALY SCORE
        # ----------------------------------------
        # Step 1: IP -> (latitude, longitude, ASN)
        lat_cur, lon_cur, asn_cur = self._lookup_ip_geo(ip_address)

        if state.last_lat is not None and state.last_lon is not None and state.last_timestamp is not None:
            # Step 2: Haversine distance from last known IP location.
            distance_km = self._haversine_km(state.last_lat, state.last_lon, lat_cur, lon_cur)

            # Step 3: Travel speed v = distance_km / delta_hours
            delta_hours = max((ts - state.last_timestamp).total_seconds() / 3600.0, EPSILON)
            v = distance_km / delta_hours

            # Step 4: Speed anomaly S_speed = min(1, v / 900)
            s_speed = min(1.0, v / 900.0)

            # Step 5: ASN change S_asn
            s_asn = 1.0 if asn_cur != state.last_asn else 0.0

            # Step 6: Historical geo deviation S_hist = distance_km / (geo_std + ε)
            geo_std = pstdev(state.geo_distances) if len(state.geo_distances) > 1 else 0.0
            s_hist = distance_km / (geo_std + EPSILON)
        else:
            # No prior geo context for first transaction.
            distance_km = 0.0
            s_speed = 0.0
            s_asn = 0.0
            s_hist = 0.0

        # Final geo score: S_geo = 0.5*S_speed + 0.3*S_hist + 0.2*S_asn
        s_geo = 0.5 * s_speed + 0.3 * s_hist + 0.2 * s_asn

        # S_geo_norm = 1 / (1 + exp(-S_geo))
        s_geo_norm = self._sigmoid(s_geo)

        # ----------------------------------------
        # 4) FINAL FRAUD RISK SCORE
        # ----------------------------------------
        # Risk_raw = 0.4*S_spend_norm + 0.3*S_velocity_norm + 0.3*S_geo_norm
        risk_raw = 0.4 * s_spend_norm + 0.3 * s_velocity_norm + 0.3 * s_geo_norm

        # Risk_final = 1 / (1 + exp(-Risk_raw))
        risk_final = self._sigmoid(risk_raw)

        # Update per-user state AFTER feature computation to preserve "historical" semantics.
        state.amounts.append(amount)
        state.timestamps.append(ts)

        if state.last_lat is not None and state.last_lon is not None:
            # Keep step distances to compute rolling geo std for future events.
            state.geo_distances.append(distance_km)

        state.last_lat = lat_cur
        state.last_lon = lon_cur
        state.last_asn = asn_cur
        state.last_timestamp = ts

        return {
            "spending_score": s_spend_norm,
            "velocity_score": s_velocity_norm,
            "geo_score": s_geo_norm,
            "fraud_risk_score": risk_final,
        }


# Global engine instance used by top-level function.
ENGINE = FraudFeatureEngine()


def compute_fraud_features(transaction: Dict[str, object]) -> Dict[str, float]:
    """Required function signature for transaction-level feature computation."""
    return ENGINE.compute_fraud_features(transaction)


def _demo_transactions() -> List[Dict[str, object]]:
    """Example test transactions for demonstration."""
    return [
        {
            "transaction_id": "T001",
            "user_id": "u_100",
            "timestamp": "2026-02-15T09:00:00",
            "amount": 1200.0,
            "ip_address": "8.8.8.8",
            "device_hash": "dev_a",
        },
        {
            "transaction_id": "T002",
            "user_id": "u_100",
            "timestamp": "2026-02-15T09:12:00",
            "amount": 1350.0,
            "ip_address": "8.8.8.8",
            "device_hash": "dev_a",
        },
        {
            "transaction_id": "T003",
            "user_id": "u_100",
            "timestamp": "2026-02-15T09:24:00",
            "amount": 42000.0,
            "ip_address": "1.1.1.1",
            "device_hash": "dev_a",
        },
        {
            "transaction_id": "T004",
            "user_id": "u_100",
            "timestamp": "2026-02-15T09:30:00",
            "amount": 1500.0,
            "ip_address": "52.95.110.1",
            "device_hash": "dev_b",
        },
        {
            "transaction_id": "T005",
            "user_id": "u_200",
            "timestamp": "2026-02-15T10:00:00",
            "amount": 500.0,
            "ip_address": "185.199.108.153",
            "device_hash": "dev_x",
        },
    ]


if __name__ == "__main__":
    print("Fraud feature engine demo output:\n")
    for tx in _demo_transactions():
        scores = compute_fraud_features(tx)
        print(f"{tx['transaction_id']} ({tx['user_id']}): {scores}")
