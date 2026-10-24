NSP default HTML error pages (REQ-PROXY-022).

Seeded from the nginx image into /data/nginx/error_pages on container start
(only missing files are copied — your edits are kept).

Mapped by nginx:
  403 → 403.html
  404 → 404.html
  429 → 429.html
  500 → 500.html
  502 → 502.html
  503 → 503.html
  504 → 504.html

After editing, run Config → Apply (or reload nginx).
