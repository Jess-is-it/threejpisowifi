ALTER TABLE captive_portal_settings
  ADD COLUMN IF NOT EXISTS speed_indicator_json JSONB NOT NULL DEFAULT '{
    "enabled": true,
    "loop_seconds": 10,
    "show_on_product_cards": true,
    "show_on_bag_items": true,
    "tiers": [
      {
        "id": "basic",
        "label": "Basic Speed",
        "min_mbps": 0,
        "max_mbps": 5,
        "color": "#fb7185",
        "glow": "#f97316",
        "flame": "#f97316",
        "smoke": "#94a3b8"
      },
      {
        "id": "steady",
        "label": "Steady Speed",
        "min_mbps": 5.01,
        "max_mbps": 20,
        "color": "#22c55e",
        "glow": "#84cc16",
        "flame": "#facc15",
        "smoke": "#cbd5e1"
      },
      {
        "id": "fast",
        "label": "Fast Speed",
        "min_mbps": 20.01,
        "max_mbps": 50,
        "color": "#38bdf8",
        "glow": "#06b6d4",
        "flame": "#60a5fa",
        "smoke": "#cbd5e1"
      },
      {
        "id": "rocket",
        "label": "Rocket Speed",
        "min_mbps": 50.01,
        "max_mbps": null,
        "color": "#a855f7",
        "glow": "#ec4899",
        "flame": "#fb923c",
        "smoke": "#e2e8f0"
      }
    ]
  }'::jsonb;

UPDATE captive_portal_settings
SET speed_indicator_json = '{
    "enabled": true,
    "loop_seconds": 10,
    "show_on_product_cards": true,
    "show_on_bag_items": true,
    "tiers": [
      {"id": "basic", "label": "Basic Speed", "min_mbps": 0, "max_mbps": 5, "color": "#fb7185", "glow": "#f97316", "flame": "#f97316", "smoke": "#94a3b8"},
      {"id": "steady", "label": "Steady Speed", "min_mbps": 5.01, "max_mbps": 20, "color": "#22c55e", "glow": "#84cc16", "flame": "#facc15", "smoke": "#cbd5e1"},
      {"id": "fast", "label": "Fast Speed", "min_mbps": 20.01, "max_mbps": 50, "color": "#38bdf8", "glow": "#06b6d4", "flame": "#60a5fa", "smoke": "#cbd5e1"},
      {"id": "rocket", "label": "Rocket Speed", "min_mbps": 50.01, "max_mbps": null, "color": "#a855f7", "glow": "#ec4899", "flame": "#fb923c", "smoke": "#e2e8f0"}
    ]
  }'::jsonb
WHERE speed_indicator_json IS NULL
   OR speed_indicator_json = '{}'::jsonb;
