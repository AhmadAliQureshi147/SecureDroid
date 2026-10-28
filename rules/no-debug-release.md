---
name: securedroid-no-debug-release
description: Refuse a debuggable application manifest
condition: "android:debuggable\\s*=\\s*\"true\""
scope: "tool:edit, tool:write"
---

Do not set android:debuggable to true. Keep debugging on the debug build type, and keep the release build type non-debuggable.
