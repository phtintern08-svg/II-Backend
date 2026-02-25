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
    
    📌 BUSINESS LOGIC:
    - "Nearby vendor" = vendor with smaller geographic distance from customer delivery location
    - Distance influences ranking (weighted score) but doesn't dominate
    - A far vendor with better capacity/stock can still rank higher than a close vendor with poor capacity
    - This balanced approach matches Amazon/Flipkart-style marketplace allocation
    
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
        Sorted by: score DESC (higher score = better match), then lead_time, then price
    """
    Vendor = models.Vendor
    VendorQuotation = models.VendorQuotation
    VendorCapacity = models.VendorCapacity
    VendorStock = getattr(models, 'VendorStock', None)

    # 📌 DISTANCE CONFIGURATION
    # MAX_DISTANCE_KM: Used for distance score normalization (closer = higher score)
    # HARD_DISTANCE_CUTOFF_KM: Optional hard filter - exclude vendors beyond this distance (None = disabled)
    # Set to None to allow all distances (only affects ranking), or set to a value (e.g., 100) to exclude far vendors
    MAX_DISTANCE_KM = 200  # Normalization factor for distance scoring
    HARD_DISTANCE_CUTOFF_KM = None  # Optional: Set to 100 to exclude vendors > 100km (None = no hard cutoff)
    
    MAX_LEAD_DAYS = 14
    WEIGHT_STOCK = 0.40
    WEIGHT_DISTANCE = 0.30  # Distance influences ranking but doesn't dominate (balanced marketplace approach)
    WEIGHT_CAPACITY = 0.20
    WEIGHT_LEAD_TIME = 0.10

    order_lat = float(order.latitude) if order.latitude else None
    order_lon = float(order.longitude) if order.longitude else None

    if not product_catalog_ids or total_qty <= 0:
        return []

    candidates = []
    
    # 🔥 HARD FILTER 1: Vendor must have approved quotation for ALL required products
    # ✅ CRITICAL CHECK: Uses func.lower() for case-insensitive status matching
    # Count distinct vendors who have approved quotations for ALL product_catalog_ids
    vendor_quotation_counts = db.session.query(
        VendorQuotation.vendor_id,
        func.count(VendorQuotation.product_id.distinct()).label('quote_count')
    ).filter(
        VendorQuotation.product_id.in_(product_catalog_ids),
        func.lower(VendorQuotation.status) == 'approved'  # ✅ Case-insensitive status check
    ).group_by(VendorQuotation.vendor_id).having(
        func.count(VendorQuotation.product_id.distinct()) == len(product_catalog_ids)
    ).all()
    
    vendor_ids = [v[0] for v in vendor_quotation_counts]
    
    if not vendor_ids:
        return []

    # 🔥 PERFORMANCE: Bulk load all vendors (prevents N+1 query explosion)
    # Instead of: for vid in vendor_ids: Vendor.query.get(vid) → 200 queries
    # Do: Vendor.query.filter(Vendor.id.in_(vendor_ids)) → 1 query
    vendors = {v.id: v for v in Vendor.query.filter(Vendor.id.in_(vendor_ids)).all()}
    
    # 🔥 PERFORMANCE: Bulk load all capacities grouped by vendor_id
    # Instead of: for each vendor, for each product → N×M queries
    # Do: Single query with filter → 1 query
    capacities = db.session.query(VendorCapacity).filter(
        VendorCapacity.vendor_id.in_(vendor_ids),
        VendorCapacity.product_catalog_id.in_(product_catalog_ids),
        VendorCapacity.is_active == True
    ).all()
    # Group by (vendor_id, product_catalog_id) for O(1) lookup
    capacity_map = {(c.vendor_id, c.product_catalog_id): c for c in capacities}
    
    # 🔥 PERFORMANCE: Bulk load all stocks grouped by vendor_id
    stocks_map = {}
    if VendorStock:
        stocks = db.session.query(VendorStock).filter(
            VendorStock.vendor_id.in_(vendor_ids),
            VendorStock.product_catalog_id.in_(product_catalog_ids)
        ).all()
        # Group by vendor_id for O(1) lookup
        for s in stocks:
            if s.vendor_id not in stocks_map:
                stocks_map[s.vendor_id] = []
            stocks_map[s.vendor_id].append(s)
    
    # 🔥 PERFORMANCE: Bulk load all quotations for primary product
    quotations = db.session.query(VendorQuotation).filter(
        VendorQuotation.vendor_id.in_(vendor_ids),
        VendorQuotation.product_id == product_catalog_ids[0],
        func.lower(VendorQuotation.status) == 'approved'
    ).all()
    quotation_map = {q.vendor_id: q for q in quotations}

    for vid in vendor_ids:
        vendor = vendors.get(vid)
        # 🔥 HARD FILTER 2: Must be verified (approved/active)
        if not vendor or vendor.verification_status not in ('approved', 'active'):
            continue

        # 🔥 HARD FILTER 3: Must have active capacity for ALL products
        # ✅ CRITICAL CHECK: Enforces (daily_capacity * lead_time_days) >= order_quantity
        # This is a HARD FILTER - vendors with insufficient capacity are EXCLUDED
        capacity_ok = True
        best_lead = MAX_LEAD_DAYS
        min_capacity = 0
        for pcid in product_catalog_ids:
            cap = capacity_map.get((vid, pcid))
            # Must have active capacity
            if not cap or cap.daily_capacity <= 0:
                capacity_ok = False
                break
            # ✅ HARD FILTER: Capacity must be sufficient - NOT just for ranking
            # daily_capacity * lead_time_days >= order_quantity
            effective_capacity = cap.daily_capacity * cap.lead_time_days
            if effective_capacity < total_qty:
                capacity_ok = False
                break
            # ✅ HARD FILTER: Bulk capacity check - max_bulk_capacity = 0 OR max_bulk_capacity >= order_quantity
            if cap.max_bulk_capacity > 0 and total_qty > cap.max_bulk_capacity:
                capacity_ok = False
                break
            best_lead = min(best_lead, cap.lead_time_days)
            if min_capacity == 0 or effective_capacity < min_capacity:
                min_capacity = effective_capacity

        if not capacity_ok:
            continue

        # 🔥 HARD FILTER 4: Stock check
        # 📌 CONCEPTUAL SEPARATION: Stock = ready goods, Capacity = production ability
        # If vendor has stock entries, use stock; if not, use capacity (made-to-order)
        # Stock is preferred for ranking but capacity can fulfill orders
        stock_available = 0
        if VendorStock:
            vendor_stocks = stocks_map.get(vid, [])
            # Sum stock across all required products
            stock_available = sum(s.available_quantity for s in vendor_stocks if s.product_catalog_id in product_catalog_ids)

        distance_km = None
        # ✅ CRITICAL FIX: Use `is not None` instead of truthy check
        # This allows 0.0 coordinates (equator/prime meridian) which are valid GPS locations
        if (
            order_lat is not None and
            order_lon is not None and
            vendor.latitude is not None and
            vendor.longitude is not None
        ):
            distance_km = haversine_km(
                order_lat, order_lon,
                float(vendor.latitude), float(vendor.longitude)
            )
            
            # 🔥 OPTIONAL HARD FILTER: Distance cutoff (operational feasibility)
            # If HARD_DISTANCE_CUTOFF_KM is set, exclude vendors beyond this distance
            # Example: HARD_DISTANCE_CUTOFF_KM = 100 → exclude vendors > 100km away
            # Set to None to disable (all distances allowed, only affects ranking)
            if HARD_DISTANCE_CUTOFF_KM is not None and distance_km > HARD_DISTANCE_CUTOFF_KM:
                continue  # Exclude vendor - too far for operational feasibility

        # Get quotation for primary product (for pricing display) - from bulk-loaded map
        quot = quotation_map.get(vid)
        base_cost = float(quot.base_cost) if quot else 0
        
        # 🔥 HARD FILTER 5: Must have valid quotation (should already be filtered, but double-check)
        if not quot:
            continue

        stock_ratio = stock_available / total_qty if total_qty else 0
        stock_score = min(stock_ratio, 1.0)

        # ✅ CRITICAL CHECK: Distance calculation safety - penalizes missing GPS (score = 0)
        # Vendors without location should NOT get neutral benefit - they should be ranked lower
        if distance_km is not None:
            distance_score = max(0, 1 - (distance_km / MAX_DISTANCE_KM))
        else:
            distance_score = 0  # Penalize vendors/orders without GPS - no neutral benefit

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

    # 🔥 DETERMINISTIC SORTING: Enterprise-grade tie-breaking for equal scores
    # Priority order:
    # 1. Higher score (descending)
    # 2. Higher stock (descending) - prefer vendors with more ready inventory
    # 3. Smaller distance (ascending) - prefer nearby vendors (9999 for missing GPS)
    # 4. Faster lead time (ascending) - prefer faster delivery
    # 5. Lower price (ascending) - prefer cheaper vendors
    candidates.sort(
        key=lambda x: (
            -x["score"],  # Higher score first
            -x["stock_available"],  # More stock preferred
            x["distance_km"] if x["distance_km"] is not None else 9999,  # Closer preferred (9999 for missing GPS)
            x["lead_time_days"],  # Faster delivery preferred
            x["base_cost_per_piece"]  # Cheaper preferred
        )
    )
    return candidates
