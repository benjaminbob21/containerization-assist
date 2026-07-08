#!/usr/bin/env node
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const catalogsDir = resolve(repoRoot, "knowledge/catalogs");
const skillsRoot = resolve(repoRoot, "skills");

const baseImageCatalog = JSON.parse(readFileSync(join(catalogsDir, "base-image-catalog.json"), "utf8"));

const simpleTableCatalogs = [
  "dockerfile-rules-catalog.json",
  "k8s-defaults-catalog.json",
  "ecosystem-catalog.json",
];

const simpleTables = {};
for (const name of simpleTableCatalogs) {
  const catalog = JSON.parse(readFileSync(join(catalogsDir, name), "utf8"));
  for (const [id, table] of Object.entries(catalog.tables)) {
    if (simpleTables[id]) throw new Error(`Duplicate table id "${id}" across catalogs`);
    simpleTables[id] = table;
  }
}

const renderTable = (columns, rowCells) => {
  const header = `| ${columns.join(" | ")} |`;
  const sep = `|${columns.map(() => "---").join("|")}|`;
  const body = rowCells.map((cells) => `| ${cells.join(" | ")} |`).join("\n");
  return `${header}\n${sep}\n${body}`;
};

const renderSimpleTable = (id) => {
  const table = simpleTables[id];
  return renderTable(table.columns, table.rows);
};

const renderMcrCatalog = () => {
  const stackBlocks = baseImageCatalog.mcr.map((stack) => {
    const columns = ["`<LV>`", ...stack.columns];
    const rows = stack.rows.map((r) => [r.version, ...r.tags.map((t) => `\`${t}\``)]);
    const table = renderTable(columns, rows);
    const heading = `**${stack.displayName} — \`${stack.registryRepo}\`**`;
    return stack.notes ? `${heading}\n\n${table}\n\n${stack.notes}` : `${heading}\n\n${table}`;
  });
  const defaultsPairs = baseImageCatalog.defaults.map((d) => `\`${d.key}=${d.version}\``);
  const wrapAt = 2;
  const first = defaultsPairs.slice(0, wrapAt).join(", ");
  const rest = defaultsPairs.slice(wrapAt).join(", ");
  const defaultsLine =
    rest.length > 0
      ? `Defaults if \`languageVersion\` is missing: ${first},\n${rest}.`
      : `Defaults if \`languageVersion\` is missing: ${first}.`;
  return `${stackBlocks.join("\n\n")}\n\n${defaultsLine}`;
};

const renderFallbackImages = () => {
  const rows = baseImageCatalog.fallbacks.rows.map((r) => [r.stackReason, r.buildStage, r.runtimeStage]);
  return renderTable(baseImageCatalog.fallbacks.columns, rows);
};

const bespokeRenderers = {
  "mcr-catalog": renderMcrCatalog,
  "fallback-images": renderFallbackImages,
};

const resolvePlaceholder = (id) => {
  if (bespokeRenderers[id]) return bespokeRenderers[id]();
  if (simpleTables[id]) return renderSimpleTable(id);
  throw new Error(`Unknown knowledge placeholder "${id}"`);
};

const findTemplates = (dir) => {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      out.push(...findTemplates(full));
    } else if (name === "SKILL.template.md") {
      out.push(full);
    }
  }
  return out;
};

const placeholderPattern = /\{\{knowledge:([\w-]+)\}\}/g;

for (const templatePath of findTemplates(skillsRoot)) {
  const outputPath = join(dirname(templatePath), "SKILL.md");
  const template = readFileSync(templatePath, "utf8");
  const rendered = template.replace(placeholderPattern, (_, id) => resolvePlaceholder(id));
  writeFileSync(outputPath, rendered);
  process.stdout.write(`wrote ${outputPath}\n`);
}
