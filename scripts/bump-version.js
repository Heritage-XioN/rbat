#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const newVersion = process.argv[2];
if (!newVersion) {
  console.error("Error: Please provide a version argument. Example: node bump-version.js 1.0.0");
  process.exit(1);
}

if (!/^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$/.test(newVersion)) {
  console.error(`Error: Invalid semver version format: "${newVersion}"`);
  process.exit(1);
}

const rootDir = path.resolve(__dirname, '..');

// Helper to update Cargo.toml [package] version
function bumpCargoToml(filePath, pkgName) {
  const absolutePath = path.join(rootDir, filePath);
  if (!fs.existsSync(absolutePath)) {
    console.warn(`Warning: File not found at ${filePath}`);
    return;
  }
  let content = fs.readFileSync(absolutePath, 'utf8');
  
  // Find [package] section and its version line
  const packageRegex = /\[package\][^]*?version\s*=\s*"([^"]+)"/;
  const match = content.match(packageRegex);
  if (!match) {
    console.error(`Error: Could not find version inside [package] in ${filePath}`);
    process.exit(1);
  }
  
  const oldVersion = match[1];
  // Replace only the version under [package]
  const updatedSection = match[0].replace(`version = "${oldVersion}"`, `version = "${newVersion}"`);
  content = content.replace(match[0], updatedSection);
  
  fs.writeFileSync(absolutePath, content, 'utf8');
  console.log(`Updated ${pkgName} (${filePath}) version from ${oldVersion} to ${newVersion}`);
}

// Helper to update package.json version
function bumpPackageJson(filePath, pkgName) {
  const absolutePath = path.join(rootDir, filePath);
  if (!fs.existsSync(absolutePath)) {
    console.warn(`Warning: File not found at ${filePath}`);
    return;
  }
  const data = JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
  const oldVersion = data.version;
  data.version = newVersion;
  fs.writeFileSync(absolutePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
  console.log(`Updated ${pkgName} (${filePath}) version from ${oldVersion} to ${newVersion}`);
}

console.log(`Bumping workspace versions to: ${newVersion}`);
bumpCargoToml('rbat-core/Cargo.toml', 'rbat-core');
bumpCargoToml('rbat-server/Cargo.toml', 'rbat-server');
bumpPackageJson('rbat-client/package.json', 'rbat-client');
console.log('Version bumping completed successfully.');
