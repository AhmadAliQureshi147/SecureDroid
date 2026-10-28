---
name: securedroid-no-world-readable
description: Refuse world-accessible Android file modes
condition: "MODE_WORLD_(READ|WRITE)ABLE"
scope: "tool:edit, tool:write"
---

Do not create files with MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE. Use MODE_PRIVATE.
