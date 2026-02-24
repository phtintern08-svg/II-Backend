"""
Vendor Recommendation Engine
Backend-controlled ranking: requirement match, stock, distance, capacity, lead time.
Deterministic, transparent, scalable to 10k+ vendors.
"""
import math
from sqlalchemy import func


def haversine_km(lat1, lon1, lat2, lon2):
    """Calculate great-circle distance in km. Returns float or None if invalid."""
    try:
        if None in (lat1, lon1, lat2, lon2):
            return None
        lat1, lon1, lat2, lon2 = map(math.radians, [float(lat1), float(lon1), float(lat2), float(lon2)])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        return 6371 * c
    except (TypeError, ValueError):
        return None


def get_recommended_vendors(order, product_catalog_ids, total_qty, db, models):
    """
    Rank vendors for an order by: requirement match, stock, distance, capacity, lead time.

    Args:
        order: Order model instance
        product_catalog_ids: list of product_catalog ids (resolved from order)
        total_qty: effective order quantity
        db: Flask-SQLAlchemy db
        models: module with Vendor, VendorQuotation, VendorCapacity, VendorStock

    Returns:
        list of dicts: [{"vendor_id", "vendor_name", "stock_available", "distance_km",
                        "capacity_available", "lead_time_days", "base_cost_per_piece",
                        "score", "breakdown": {...}}, ...]
    """
    Vendor = models.Vendor
    VendorQuotation = models.VendorQuotation
    VendorCapacity = models.VendorCapacity
    VendorStock = getattr(models, 'VendorStock', None)

    MAX_DISTANCE_KM = 200
    MAX_LEAD_DAYS = 14
    WEIGHT_STOCK = 0.40
    WEIGHT_DISTANCE = 0.30
    WEIGHT_CAPACITY = 0.20
    WEIGHT_LEAD_TIME = 0.10

    order_lat = float(order.latitude) if order.latitude else None
    order_lon = float(order.longitude) if order.longitude else None

    if not product_catalog_ids or total_qty <= 0:
        return []

    candidates = []
    vendor_ids = db.session.query(VendorQuotation.vendor_id).filter(
        VendorQuotation.product_id.in_(product_catalog_ids),
        func.lower(VendorQuotation.status) == 'approved'
    ).distinct().all()
    vendor_ids = [v[0] for v in vendor_ids]

    for vid in vendor_ids:
        vendor = Vendor.query.get(vid)
        if not vendor or vendor.verification_status not in ('approved', 'active'):
            continue

        capacity_ok = True
        best_lead = MAX_LEAD_DAYS
        min_capacity = 0
        for pcid in product_catalog_ids:
            cap = VendorCapacity.query.filter_by(
                vendor_id=vid,
                product_catalog_id=pcid,
                is_active=True
            ).first()
            if not cap or cap.daily_capacity <= 0:
                capacity_ok = False
                break
            required_days = (total_qty + cap.daily_capacity - 1) // cap.daily_capacity if cap.daily_capacity else 999
            if required_days > cap.lead_time_days:
                capacity_ok = False
                break
            if cap.max_bulk_capacity > 0 and total_qty > cap.max_bulk_capacity:
                capacity_ok = False
                break
            best_lead = min(best_lead, cap.lead_time_days)
            effective_capacity = cap.daily_capacity * cap.lead_time_days
            if min_capacity == 0 or effective_capacity < min_capacity:
                min_capacity = effective_capacity

        if not capacity_ok:
            continue

        stock_available = 0
        if VendorStock:
            stocks = VendorStock.query.filter(
                VendorStock.vendor_id == vid,
                VendorStock.product_catalog_id.in_(product_catalog_ids)
            ).all()
            stock_available = sum(s.available_quantity for s in stocks)

        distance_km = None
        if order_lat is not None and order_lon is not None and vendor.latitude and vendor.longitude:
            distance_km = haversine_km(
                order_lat, order_lon,
                float(vendor.latitude), float(vendor.longitude)
            )

        quot = VendorQuotation.query.filter_by(
            vendor_id=vid,
            product_id=product_catalog_ids[0],
            status='approved'
        ).first()
        base_cost = float(quot.base_cost) if quot else 0

        stock_ratio = stock_available / total_qty if total_qty else 0
        stock_score = min(stock_ratio, 1.0)

        if distance_km is not None:
            distance_score = max(0, 1 - (distance_km / MAX_DISTANCE_KM))
        else:
            distance_score = 0.5

        capacity_ratio = min_capacity / total_qty if total_qty else 0
        capacity_score = min(capacity_ratio, 1.0)

        lead_time_score = max(0, 1 - (best_lead / MAX_LEAD_DAYS))

        score = (
            WEIGHT_STOCK * stock_score +
            WEIGHT_DISTANCE * distance_score +
            WEIGHT_CAPACITY * capacity_score +
            WEIGHT_LEAD_TIME * lead_time_score
        )

        candidates.append({
            "vendor_id": vid,
            "vendor_name": vendor.business_name or vendor.username or f"Vendor #{vid}",
            "stock_available": stock_available,
            "distance_km": round(distance_km, 2) if distance_km is not None else None,
            "capacity_available": min_capacity,
            "lead_time_days": best_lead,
            "base_cost_per_piece": base_cost,
            "city": vendor.city,
            "state": vendor.state,
            "score": round(score, 2),
            "breakdown": {
                "stock_score": round(stock_score, 2),
                "distance_score": round(distance_score, 2),
                "capacity_score": round(capacity_score, 2),
                "lead_time_score": round(lead_time_score, 2),
            }
        })

    candidates.sort(key=lambda x: (-x["score"], x["lead_time_days"], x["base_cost_per_piece"]))
    return candidates
