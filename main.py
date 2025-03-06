import discord
from discord import app_commands
from discord.ext import commands
import os
import hashlib
import base64
from dotenv import load_dotenv
import vt
import asyncio

load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents, status=discord.Status.dnd)
vt_client = vt.Client(VT_API_KEY)

# Helper function to run VT sync functions in a thread pool
async def run_vt_async(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name} ({bot.user.id})')
    await bot.change_presence(
        status=discord.Status.dnd,
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="your files safety"
        )
    )
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Failed to sync commands: {e}")

@bot.tree.command(name="scan", description="Scan a URL for malware")
@app_commands.describe(url="The URL to scan")
@app_commands.checks.cooldown(1, 10, key=lambda i: i.user.id)
async def scan_url(interaction: discord.Interaction, url: str):
    if not url.startswith(('http://', 'https://')):
        await interaction.response.send_message("Please use a valid URL starting with http:// or https://", ephemeral=True)
        return

    try:
        await interaction.response.defer()

        # Generate URL ID
        url_hash = hashlib.sha256(url.encode()).digest()
        url_id = base64.urlsafe_b64encode(url_hash).decode().strip('=')

        try:
            # Use synchronous client methods with our async helper
            url_report = await run_vt_async(vt_client.get_object, f"/urls/{url_id}")
            stats = url_report.last_analysis_stats
            result = (
                f"**Scan results for {url}**\n"
                f"✅ **Malicious**: {stats.get('malicious', 0)}\n"
                f"✅ **Undetected**: {stats.get('undetected', 0)}\n"
                f"🔗 [View on VirusTotal]({url_report.url})"
            )
            await interaction.followup.send(result)
        except vt.APIError as e:
            if e.code == 'NotFoundError':
                await interaction.followup.send("Submitting URL for analysis...")
                analysis = await run_vt_async(vt_client.scan_url, url)
                analysis_url = f"https://www.virustotal.com/gui/analysis/{analysis.id}"
                await interaction.followup.send(f"Analysis submitted!\n🔗 [View results]({analysis_url})")
            else:
                await interaction.followup.send(f"Error: {e.message}")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="scanfile", description="Scan a file for malware")
@app_commands.describe(file="The file to scan")
@app_commands.checks.cooldown(1, 10, key=lambda i: i.user.id)
async def scan_file(interaction: discord.Interaction, file: discord.Attachment):
    if file.size > 32 * 1024 * 1024:
        await interaction.response.send_message("File size exceeds 32MB limit.", ephemeral=True)
        return

    try:
        await interaction.response.defer()
        file_content = await file.read()
        sha256 = hashlib.sha256(file_content).hexdigest()

        try:
            # Use synchronous client methods with our async helper
            vt_file = await run_vt_async(vt_client.get_object, f"/files/{sha256}")
            stats = vt_file.last_analysis_stats
            result = (
                f"**Scan results for {file.filename}**\n"
                f"✅ **Malicious**: {stats.get('malicious', 0)}\n"
                f"✅ **Undetected**: {stats.get('undetected', 0)}\n"
                f"🔗 [View on VirusTotal](https://www.virustotal.com/gui/file/{sha256})"
            )
            await interaction.followup.send(result)
        except vt.APIError as e:
            if e.code == 'NotFoundError':
                await interaction.followup.send("Submitting file for analysis...")
                analysis = await run_vt_async(vt_client.scan_file, file_content)
                analysis_url = f"https://www.virustotal.com/gui/analysis/{analysis.id}"
                await interaction.followup.send(f"Analysis submitted!\n🔗 [View results]({analysis_url})")
            else:
                await interaction.followup.send(f"Error: {e.message}")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.CommandOnCooldown):
        await interaction.response.send_message(
            f"Please wait {error.retry_after:.1f} seconds before using this command again.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"An error occurred: {str(error)}",
            ephemeral=True
        )

bot.run(TOKEN)