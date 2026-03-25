#!/usr/bin/env node

import { Command } from 'commander';
import { runScan } from '../src/index.js';
import chalk from 'chalk';

const program = new Command();

program
  .name('shipwryte-scan')
  .description('Free security scanner for AI-generated code')
  .version('0.1.0')
  .argument('[path]', 'Path to scan', '.')
  .option('-o, --output <format>', 'Output format: markdown, json, html', 'markdown')
  .option('-f, --file <path>', 'Output file path (defaults to shipwryte-report.{ext})')
  .option('--no-secrets', 'Skip secret detection')
  .option('--no-deps', 'Skip dependency scanning')
  .option('--no-sast', 'Skip static analysis')
  .option('--severity <level>', 'Minimum severity to report: low, medium, high, critical', 'low')
  .option('--json', 'Output raw JSON to stdout')
  .option('-q, --quiet', 'Suppress progress output')
  .action(async (targetPath, options) => {
    if (!options.quiet && !options.json) {
      console.log('');
      console.log(chalk.bold.cyan('  ⚓ Shipwryte Scan v0.1.0'));
      console.log(chalk.gray('  Free security scanner for AI-generated code'));
      console.log('');
    }

    try {
      await runScan(targetPath, options);
    } catch (err) {
      console.error(chalk.red(`\n  Error: ${err.message}`));
      process.exit(1);
    }
  });

program.parse();
