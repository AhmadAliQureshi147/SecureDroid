import type { ManifestComponent, ParsedManifest } from "./types.ts";
import { lineAt } from "./text.ts";

function attr(source: string, name: string): string | undefined {
  const match = new RegExp(`android:${name}\\s*=\\s*"([^"]*)"`).exec(source);
  return match?.[1];
}

function parseComponent(kind: ManifestComponent["kind"], raw: string, body: string, index: number, text: string): ManifestComponent {
  const header = raw;
  const actions = [...body.matchAll(/android:name="([^"]+)"/g)]
    .map((match) => match[1] ?? "")
    .filter((name) => name.startsWith("android.intent.action.") || name.includes("."));
  const actionNames = [...body.matchAll(/<action\b[^>]*android:name="([^"]+)"/g)].map((match) => match[1] ?? "");
  const categories = [...body.matchAll(/<category\b[^>]*android:name="([^"]+)"/g)].map((match) => match[1] ?? "");
  const exported = attr(header, "exported");
  return {
    kind,
    name: attr(header, "name") ?? "(unnamed)",
    exported: exported === "true" ? true : exported === "false" ? false : "unspecified",
    permission: attr(header, "permission") ?? attr(header, "readPermission") ?? attr(header, "writePermission"),
    grantUriPermissions: attr(header, "grantUriPermissions") === "true",
    actions: actionNames.length > 0 ? actionNames : actions,
    categories,
    line: lineAt(text, index),
  };
}

export function parseManifest(path: string, text: string): ParsedManifest {
  const components: ManifestComponent[] = [];
  const pattern = /<(activity|service|receiver|provider)\b([^>]*?)(?:\/>|>([\s\S]*?)<\/\1>)/g;
  for (const match of text.matchAll(pattern)) {
    const kind = match[1] as ManifestComponent["kind"];
    components.push(parseComponent(kind, match[2] ?? "", match[3] ?? "", match.index ?? 0, text));
  }
  const application = /<application\b([^>]*)>/.exec(text)?.[1] ?? "";
  return {
    path,
    packageName: /package="([^"]+)"/.exec(text)?.[1],
    debuggable: attr(application, "debuggable") === "true" || /android:debuggable\s*=\s*"true"/.test(text),
    allowBackup: attr(application, "allowBackup") === "true",
    usesCleartextTraffic: attr(application, "usesCleartextTraffic") === "true",
    networkSecurityConfig: attr(application, "networkSecurityConfig"),
    components,
  };
}

export function isLauncher(component: ManifestComponent): boolean {
  return (
    component.actions.includes("android.intent.action.MAIN") &&
    component.categories.includes("android.intent.category.LAUNCHER")
  );
}

const PROTECTED_BROADCASTS = new Set([
  "android.intent.action.BOOT_COMPLETED",
  "android.intent.action.LOCKED_BOOT_COMPLETED",
  "android.intent.action.MY_PACKAGE_REPLACED",
  "android.intent.action.ACTION_MY_PACKAGE_REPLACED",
]);

export function onlyProtectedBroadcasts(component: ManifestComponent): boolean {
  return component.actions.length > 0 && component.actions.every((action) => PROTECTED_BROADCASTS.has(action));
}
