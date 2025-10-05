import os
import json
from pathlib import Path
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from api.droppers.services.compilation.builder import DropperBuilder, CompilationError

console = Console()

class Command(BaseCommand):
    help = 'Build a dropper with customizable options using Rich for CLI output'

    def add_arguments(self, parser):
        parser.add_argument(
            '-c', '--config',
            type=str,
            help='Path to JSON configuration file'
        )
        parser.add_argument(
            '-o', '--output',
            type=str,
            default='dropper.exe',
            help='Output filename (default: dropper.exe)'
        )
        parser.add_argument(
            '--debug',
            action='store_true',
            help='Enable debug mode'
        )
        parser.add_argument(
            '--hide-console',
            action='store_true',
            help='Hide console window'
        )
        parser.add_argument(
            '--list-features',
            action='store_true',
            help='List all available features and exit'
        )

    def handle(self, *args, **options):
        if options['list_features']:
            self.list_features()
            return

        try:
            config = self.load_config(options)
            self.build_dropper(config, options['output'])
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            raise CommandError(str(e)) from e

    def load_config(self, options):
        """Load configuration from file or use command line options."""
        if options['config']:
            try:
                with open(options['config'], 'r') as f:
                    config = json.load(f)
            except Exception as e:
                raise CommandError(f"Failed to load config file: {e}")
        else:
            config = {
                'filename': options['output'],
                'debug_mode': options['debug'],
                'hide_console': options['hide_console'],
                'preprocessing_macros': self.get_default_macros(options)
            }
        return config

    def get_default_macros(self, options):
        """Get default macros based on command line options."""
        macros = []
        if options['debug_mode']:
            macros.append('DEBUG')
        return macros

    def build_dropper(self, config, output_file):
        """Build the dropper with the given configuration."""
        console.print(Panel.fit(
            "🚀 [bold blue]Dropper Builder[/]",
            border_style="blue"
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Building dropper...", total=100)

            try:
                builder = DropperBuilder(config)
                result = builder.build()
                
                progress.update(task, completed=100)
                console.print("\n[bold green]✓ Build completed successfully![/]")
                
                # Show build summary
                self.show_build_summary(config, result['output_path'])
                
            except CompilationError as e:
                console.print(f"\n[bold red]✗ Build failed:[/] {str(e)}")
                raise CommandError("Dropper build failed") from e

    def show_build_summary(self, config, output_path):
        """Display a summary of the build."""
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="white")
        
        table.add_row("Output File", str(output_path))
        table.add_row("Debug Mode", "✅ Enabled" if config.get('debug_mode') else "❌ Disabled")
        table.add_row("Hide Console", "✅ Enabled" if config.get('hide_console') else "❌ Disabled")
        
        if config.get('preprocessing_macros'):
            macros = "\n".join(f"• {macro}" for macro in config['preprocessing_macros'])
            table.add_row("Features", macros)
        
        console.print("\n[bold]Build Summary:[/]")
        console.print(table)

    def list_features(self):
        """List all available features/macros."""
        features = {
            "Core Features": [
                "DEBUG - Enable debug output",
                "ANTI_ANALYSIS_ENABLED - Enable anti-analysis techniques",
                "ENCRYPTED_PAYLOAD - Enable payload encryption",
                "REMOTE_PROCESS_INJECTION - Enable remote process injection"
            ],
            "Injection Methods": [
                "APC_INJECTION - Use APC for injection",
                "EARLY_BIRD_INJECTION - Use early bird APC injection",
                "FUNCTION_STOMPING - Use function stomping"
            ],
            "Obfuscation": [
                "OBFUSCATED_PAYLOAD - Enable payload obfuscation",
                "IPV4_OBFUSCATION - Use IPv4 address obfuscation",
                "UUID_OBFUSCATION - Use UUID obfuscation"
            ]
        }

        console.print("\n[bold blue]Available Features:[/]")
        for category, items in features.items():
            console.print(f"\n[bold]{category}:[/]")
            for item in items:
                console.print(f"  • {item}")

        console.print("\n[dim]Use these feature names with --config or in your JSON config file.[/]")