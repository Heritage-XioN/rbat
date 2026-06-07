#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');

// 1. Get version of rbat-core (rbat)
const coreCargoPath = path.join(rootDir, 'rbat-core/Cargo.toml');
if (!fs.existsSync(coreCargoPath)) {
  console.error("Error: rbat-core/Cargo.toml not found!");
  process.exit(1);
}
const coreContent = fs.readFileSync(coreCargoPath, 'utf8');
const coreMatch = coreContent.match(/\[package\][^]*?version\s*=\s*"([^"]+)"/);
if (!coreMatch) {
  console.error("Error: Could not extract version from rbat-core/Cargo.toml");
  process.exit(1);
}
const coreVersion = coreMatch[1];
console.log(`Detected rbat version: ${coreVersion}`);

// 2. Update rbat-server's dependency
const serverCargoPath = path.join(rootDir, 'rbat-server/Cargo.toml');
if (!fs.existsSync(serverCargoPath)) {
  console.error("Error: rbat-server/Cargo.toml not found!");
  process.exit(1);
}
let serverContent = fs.readFileSync(serverCargoPath, 'utf8');

// Replace: rbat = { path = "../rbat-core"}
// With: rbat = { version = "coreVersion", path = "../rbat-core" }
const searchPattern = /rbat\s*=\s*\{\s*path\s*=\s*"[^"]+"\s*\}/g;
const replacement = `rbat = { version = "${coreVersion}", path = "../rbat-core" }`;

if (!searchPattern.test(serverContent)) {
  // Try matching more relaxed whitespace
  const flexiblePattern = /rbat\s*=\s*\{\s*path\s*=\s*"[^"]+"\s*,\s*version\s*=\s*"[^"]+"\s*\}/g;
  if (flexiblePattern.test(serverContent)) {
    console.log("Dependency rbat already has version specified. Updating it...");
    serverContent = serverContent.replace(flexiblePattern, replacement);
  } else {
    console.error("Error: Could not find dependency line: rbat = { path = \"../rbat-core\" } in rbat-server/Cargo.toml");
    process.exit(1);
  }
} else {
  serverContent = serverContent.replace(searchPattern, replacement);
}

fs.writeFileSync(serverCargoPath, serverContent, 'utf8');
console.log(`Successfully updated rbat-server/Cargo.toml to use rbat version: ${coreVersion}`);
