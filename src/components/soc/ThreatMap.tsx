import { useEffect, useRef, useState } from "react";
import type { IpIntel } from "@/lib/types";

/**
 * Leaflet / OpenStreetMap map. Leaflet is browser-only, so it is imported
 * dynamically after mount — never during server rendering.
 */
export function ThreatMap({ points, height = 420 }: { points: IpIntel[]; height?: number }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<unknown>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let disposed = false;
    let cleanup: (() => void) | undefined;

    (async () => {
      try {
        const L = (await import("leaflet")).default;
        if (disposed || !ref.current) return;
        const first = points[0];
        const map = L.map(ref.current, { zoomControl: true, attributionControl: true, scrollWheelZoom: false }).setView(
          first ? [first.lat, first.lon] : [20, 10],
          first ? 5 : 2,
        );
        mapRef.current = map;
        L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
          maxZoom: 18,
          attribution: "&copy; OpenStreetMap contributors",
        }).addTo(map);

        const bounds: [number, number][] = [];
        points.forEach((p) => {
          const color =
            p.risk === "CRITICAL" ? "#f4553d" : p.risk === "HIGH" || p.risk === "MEDIUM" ? "#f0a54a" : "#3fd995";
          L.circleMarker([p.lat, p.lon], {
            radius: 9,
            color,
            weight: 2,
            fillColor: color,
            fillOpacity: 0.35,
          })
            .addTo(map)
            .bindPopup(
              `<strong>${p.ip}</strong><br/>${p.city || "UNKNOWN"}, ${p.country || "UNKNOWN"}<br/>${p.isp || "UNKNOWN"} (${p.asn || "?"})<br/>Abuse score: ${p.abuseScore}/100<br/><em>Approximate IP geolocation${
                p.accuracy_radius_km ? ` · accuracy radius ${p.accuracy_radius_km} km` : ""
              }</em>`,
            );
          // Accuracy-radius circle when available; otherwise a conservative
          // 150 km display halo so the dot is never read as an exact address.
          const radiusKm = p.accuracy_radius_km && p.accuracy_radius_km > 0 ? p.accuracy_radius_km : 150;
          L.circle([p.lat, p.lon], { radius: radiusKm * 1000, color, weight: 1, opacity: 0.35, fillOpacity: 0.08 }).addTo(map);
          bounds.push([p.lat, p.lon]);
        });
        if (bounds.length > 1) map.fitBounds(bounds, { padding: [40, 40] });
        setTimeout(() => map.invalidateSize(), 150);

        cleanup = () => map.remove();
      } catch {
        setFailed(true);
      }
    })();

    return () => {
      disposed = true;
      cleanup?.();
      mapRef.current = null;
    };
  }, [points]);

  if (failed) {
    return (
      <div className="grid place-items-center rounded-lg border border-border bg-muted/30 text-sm text-muted-foreground" style={{ height }}>
        Map could not be loaded. Coordinates are still listed below.
      </div>
    );
  }

  return <div ref={ref} className="overflow-hidden rounded-lg border border-border" style={{ height }} />;
}
