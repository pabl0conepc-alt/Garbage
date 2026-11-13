"""Build web/world.json from Natural Earth 1:110m GeoJSON (public domain).

Usage: python tools/build_world_map.py ne_110m_land.geojson \
       ne_110m_admin_0_boundary_lines_land.geojson web/world.json

Source used: nvkelso/natural-earth-vector v5.1.2, geojson/ directory.
"""
import json, sys
land_path, borders_path, out_path = sys.argv[1:4]

def ring(points):
    out = []
    for index, (lon, lat) in enumerate(points):
        x, y = round(lon + 180, 2), round(90 - lat, 2)
        out.append(("M" if index == 0 else "L") + f"{x:g} {y:g}")
    return "".join(out)

def paths(geojson, closed):
    parts = []
    for feature in geojson["features"]:
        geometry = feature["geometry"]
        kind, coordinates = geometry["type"], geometry["coordinates"]
        if kind == "Polygon": groups = [coordinates]
        elif kind == "MultiPolygon": groups = coordinates
        elif kind == "LineString": groups = [[coordinates]]
        elif kind == "MultiLineString": groups = [[line] for line in coordinates]
        else: continue
        for group in groups:
            for line in group:
                parts.append(ring(line) + ("Z" if closed else ""))
    return "".join(parts)

land = json.load(open(land_path))
borders = json.load(open(borders_path))
data = {
    "source": "Natural Earth 1:110m land and land boundary lines, v5.1.2 (public domain), naturalearthdata.com",
    "projection": "equirectangular; x = longitude + 180, y = 90 - latitude",
    "width": 360, "height": 180,
    "land": paths(land, True),
    "borders": paths(borders, False),
}
json.dump(data, open(out_path, "w"), separators=(",", ":"))
print(len(data["land"]), len(data["borders"]))
