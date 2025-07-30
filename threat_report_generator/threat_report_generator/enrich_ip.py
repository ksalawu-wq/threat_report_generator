def enrich_ip(ip):
    import requests
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        return {
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "org": data.get("org"),
            "isp": data.get("isp")
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}
