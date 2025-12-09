def analyze_deal(deal: dict) -> dict:
    arv = deal['price'] * 3.2  # conservative comps
    repair = 25000
    profit = arv - deal['price'] - repair - 15000
    score = min(100, int((profit / 100000) * 100))
    return {
        "arv": int(arv),
        "repair_cost": repair,
        "profit": int(profit),
        "score": score,
        "recommend": score >= 75
    }
