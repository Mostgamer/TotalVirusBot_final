import discord
from discord import app_commands
from discord.ext import commands
import os
import hashlib
import base64
from dotenv import load_dotenv
import vt

load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents, status=discord.Status.dnd)
vt_client = vt.Client(VT_API_KEY)

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
        for command in synced:
            print(f"Registered command: /{command.name}")
    except Exception as e:
        print(f"Failed to sync commands: {e}")

@bot.tree.command(name="ping", description="Check bot's latency")
async def ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    print(f"[COMMAND] Ping command executed by {interaction.user.name} (ID: {interaction.user.id}) with latency {latency}ms")
    await interaction.response.send_message(f"pong! ({latency}ms)")
    print(f"[RESPONSE] Sent ping response to {interaction.user.name}: {latency}ms")

@bot.tree.command(name="scan", description="Scan a URL for malware")
@app_commands.describe(url="The URL to scan")
@app_commands.checks.cooldown(1, 10, key=lambda i: i.user.id)
async def scan_url(interaction: discord.Interaction, url: str):
    print(f"[COMMAND] URL scan requested by {interaction.user.name} (ID: {interaction.user.id}) for URL: {url}")
    
    if not url.startswith(('http://', 'https://')):
        print(f"[ERROR] Invalid URL format: {url} - missing http:// or https://")
        await interaction.response.send_message("Please use a valid URL starting with http:// or https://", ephemeral=True)
        return

    try:
        await interaction.response.defer()
        print(f"[INFO] Response deferred for URL scan of {url}")

        # Generate URL ID
        url_hash = hashlib.sha256(url.encode()).digest()
        url_id = base64.urlsafe_b64encode(url_hash).decode().strip('=')
        print(f"[DEBUG] Generated URL ID: {url_id} for {url}")

        try:
            # Use proper async method
            print(f"[INFO] Attempting to get URL report for {url}")
            url_report = await vt_client.get_object_async(f"/urls/{url_id}")
            stats = url_report.last_analysis_stats
            print(f"[SUCCESS] Got URL report. Stats: {stats}")
            
            result = (
                f"**Scan results for {url}**\n"
                f"✅ **Malicious**: {stats.get('malicious', 0)}\n"
                f"✅ **Undetected**: {stats.get('undetected', 0)}\n"
                f"🔗 [View on VirusTotal]({url_report.url})"
            )
            await interaction.followup.send(result)
            print(f"[RESPONSE] Sent URL scan results to {interaction.user.name}")
        except vt.APIError as e:
            print(f"[API ERROR] {e.code}: {e.message}")
            if e.code == 'NotFoundError':
                print(f"[INFO] URL not found, submitting for analysis: {url}")
                await interaction.followup.send("Submitting URL for analysis...")
                # Use proper async scan method
                analysis = await vt_client.scan_url_async(url)
                analysis_url = f"https://www.virustotal.com/gui/analysis/{analysis.id}"
                await interaction.followup.send(f"Analysis submitted!\n🔗 [View results]({analysis_url})")
                print(f"[SUCCESS] URL submitted for analysis. Analysis ID: {analysis.id}")
            else:
                await interaction.followup.send(f"Error: {e.message}")
                print(f"[ERROR] Failed to handle URL scan: {e.message}")
    except Exception as e:
        print(f"[EXCEPTION] Unhandled error during URL scan: {str(e)}")
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.command(name="scanfile", description="Scan a file for malware")
@app_commands.describe(file="The file to scan")
@app_commands.checks.cooldown(1, 10, key=lambda i: i.user.id)
async def scan_file(interaction: discord.Interaction, file: discord.Attachment):
    print(f"[COMMAND] File scan requested by {interaction.user.name} (ID: {interaction.user.id}) for file: {file.filename} ({file.size} bytes)")
    
    if file.size > 32 * 1024 * 1024:
        print(f"[ERROR] File too large: {file.filename} ({file.size} bytes)")
        await interaction.response.send_message("File size exceeds 32MB limit.", ephemeral=True)
        return

    try:
        await interaction.response.defer()
        print(f"[INFO] Response deferred for file scan of {file.filename}")
        
        file_content = await file.read()
        sha256 = hashlib.sha256(file_content).hexdigest()
        print(f"[DEBUG] File SHA256: {sha256}")

        try:
            # Use proper async method
            print(f"[INFO] Attempting to get file report for {file.filename}")
            vt_file = await vt_client.get_object_async(f"/files/{sha256}")
            stats = vt_file.last_analysis_stats
            print(f"[SUCCESS] Got file report. Stats: {stats}")
            
            result = (
                f"**Scan results for {file.filename}**\n"
                f"✅ **Malicious**: {stats.get('malicious', 0)}\n"
                f"✅ **Undetected**: {stats.get('undetected', 0)}\n"
                f"🔗 [View on VirusTotal](https://www.virustotal.com/gui/file/{sha256})"
            )
            await interaction.followup.send(result)
            print(f"[RESPONSE] Sent file scan results to {interaction.user.name}")
        except vt.APIError as e:
            print(f"[API ERROR] {e.code}: {e.message}")
            if e.code == 'NotFoundError':
                print(f"[INFO] File not found, submitting for analysis: {file.filename}")
                await interaction.followup.send("Submitting file for analysis...")
                # Use proper async scan method
                analysis = await vt_client.scan_file_async(file_content)
                analysis_url = f"https://www.virustotal.com/gui/analysis/{analysis.id}"
                await interaction.followup.send(f"Analysis submitted!\n🔗 [View results]({analysis_url})")
                print(f"[SUCCESS] File submitted for analysis. Analysis ID: {analysis.id}")
            else:
                await interaction.followup.send(f"Error: {e.message}")
                print(f"[ERROR] Failed to handle file scan: {e.message}")
    except Exception as e:
        print(f"[EXCEPTION] Unhandled error during file scan: {str(e)}")
        await interaction.followup.send(f"❌ Error: {str(e)}")

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    print(f"[ERROR] Command error for {interaction.command.name if interaction.command else 'unknown command'}: {str(error)}")
    
    if isinstance(error, app_commands.CommandOnCooldown):
        print(f"[COOLDOWN] User {interaction.user.name} hit cooldown: {error.retry_after:.1f}s remaining")
        await interaction.response.send_message(
            f"Please wait {error.retry_after:.1f} seconds before using this command again.",
            ephemeral=True
        )
    else:
        print(f"[UNHANDLED ERROR] {type(error).__name__}: {str(error)}")
        await interaction.response.send_message(
            f"An error occurred: {str(error)}",
            ephemeral=True
        )

bot.run(TOKEN)