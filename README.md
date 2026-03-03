# Meow Mod Analyzer 🐱🔍

**Meow Mod Analyzer** is a lightweight PowerShell script designed to help Minecraft players scan their `mods` folder for potentially malicious, cracked, or cheat-related mod files.

The tool performs two main analysis passes:

1. **Fast verification** against legitimate mod databases (Modrinth API + Megabase)
2. **Deep content inspection** of unverified JAR files for known suspicious patterns commonly found in hacked clients, ghost clients, and malicious mods (2025–2026 edition)

## Features

- Beautiful ASCII art banner & clean console interface
- Automatic detection of default Minecraft mods folder
- SHA-1 hash lookup against Modrinth and Megabase databases
- Zone.Identifier analysis to detect common suspicious download sources (MediaFire, Discord, Google Drive, cracked client sites, etc.)
- Deep scanning of JAR contents (class files, JSON, MANIFEST.MF) for cheat-related strings, namespaces, mixins, and obfuscation patterns
- Clear categorized output:  
  ✅ Verified legitimate mods  
  ❓ Unknown mods (with download source hint)  
  🚨 Suspicious / potentially dangerous mods
- Running Minecraft instance uptime display (when detectable)
- Safe error handling and user-friendly feedback

## Screenshots

*(Add 1–3 screenshots here after running the script – recommended: clean summary output, suspicious mod block example, verified + unknown mods view)*

## Requirements

- Windows (PowerShell 5.1 or later – works in PowerShell 7 too)
- Internet connection (required for Modrinth & Megabase API queries)
- Minecraft mods folder containing `.jar` files

No additional modules or installations are required — the script uses only built-in .NET/PowerShell capabilities.

## Usage

1. Save the script as `Meow-Mod-Analyzer.ps1`
2. Open PowerShell (recommended: run as normal user — **not** Administrator)
3. Navigate to the script folder:

   ```powershell
   cd path\to\script\folder
