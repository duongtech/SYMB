import { Command } from "commander";
import chalk from "chalk";
import fs from "fs";
import path from "path";
import os from "os";

const program = new Command();

program
  .name("symb")
  .description("SYMB: Symbolic Reverse Engineering & Deobfuscation for AI Agents")
  .version("1.0.0");

program
  .command("setup")
  .description("Register SYMB MCP server with your AI coding agents (Claude, Cursor, Antigravity)")
  .action(async () => {
    console.log(chalk.bold.cyan("\n⚡ SYMB AGENT REGISTRATION WIZARD\n"));

    // Check Claude Code / Desktop
    const claudeConfigPath = path.join(
      os.homedir(),
      "AppData",
      "Roaming",
      "Claude",
      "claude_desktop_config.json"
    );

    let registeredCount = 0;

    try {
      if (fs.existsSync(claudeConfigPath)) {
        const raw = fs.readFileSync(claudeConfigPath, "utf-8");
        const cfg = JSON.parse(raw);
        cfg.mcpServers = cfg.mcpServers || {};
        cfg.mcpServers.symb = {
          command: "npx",
          args: ["-y", "symb-agents"]
        };
        fs.writeFileSync(claudeConfigPath, JSON.stringify(cfg, null, 2), "utf-8");
        console.log(chalk.green("✔ Registered SYMB with Claude Desktop"));
        registeredCount++;
      }
    } catch {}

    // Check Cursor Global / Workspace
    const cursorConfigPath = path.join(
      os.homedir(),
      ".cursor",
      "mcp.json"
    );

    try {
      if (!fs.existsSync(path.dirname(cursorConfigPath))) {
        fs.mkdirSync(path.dirname(cursorConfigPath), { recursive: true });
      }
      let cfg: any = { mcpServers: {} };
      if (fs.existsSync(cursorConfigPath)) {
        cfg = JSON.parse(fs.readFileSync(cursorConfigPath, "utf-8"));
      }
      cfg.mcpServers = cfg.mcpServers || {};
      cfg.mcpServers.symb = {
        command: "npx",
        args: ["-y", "symb-agents"]
      };
      fs.writeFileSync(cursorConfigPath, JSON.stringify(cfg, null, 2), "utf-8");
      console.log(chalk.green("✔ Registered SYMB with Cursor IDE"));
      registeredCount++;
    } catch {}

    console.log(chalk.bold.green(`\n🎉 SYMB successfully registered with ${registeredCount} agent environment(s)!`));
    console.log(chalk.dim("Restart your AI agent or reload window to start using SYMB tools.\n"));
  });

program
  .command("solve <target>")
  .description("Solve reachability constraints for a target binary address")
  .option("-b, --binary <path>", "Path to binary")
  .action((target, options) => {
    console.log(chalk.cyan(`Solving path to ${target} in ${options.binary || "target binary"}...`));
  });

program.parse(process.argv);
