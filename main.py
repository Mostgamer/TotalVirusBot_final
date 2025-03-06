import discord
from discord.ext import commands
from discord import app_commands
import os
import hashlib
import base64
from dotenv import load_dotenv
import vt

load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents)
vt_client = vt.Client(VT_API_KEY)

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name} ({bot.user.id})')
    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Failed to sync commands: {e}")

@bot.command()
@commands.cooldown(1, 60, commands.BucketType.user)
async def scanfile(ctx):
    if not ctx.message.attachments:
        await ctx.send("Please attach a file to scan.")
        return

    attachment = ctx.message.attachments[0]

    if attachment.size > 32 * 1024 * 1024:
        await ctx.send("File size exceeds 32MB limit.")
        return

    try:
        msg = await ctx.send("Processing file...")
        file_content = await attachment.read()
        sha256 = hashlib.sha256(file_content).hexdigest()

        try:
            file = await vt_client.get_object_async(f"/files/{sha256}")
            stats = file.last_analysis_stats
            result = (
                f"**Scan results for {attachment.filename}**\n"
                f"✅ **Malicious**: {stats.get('malicious', 0)}\n"
                f"✅ **Undetected**: {stats.get('undetected', 0)}\n"
                f"🔗 [View on VirusTotal](https://www.virustotal.com/gui/file/{sha256})"
            )
            await msg.edit(content=result)
        except vt.APIError as e:
            if e.code == 'NotFoundError':
                await msg.edit(content="Submitting file for analysis...")
                analysis = await vt_client.scan_file_async(file_content)
                analysis_url = f"https://www.virustotal.com/gui/analysis/{analysis.id}"
                await msg.edit(content=f"Analysis submitted!\n🔗 [View results]({analysis_url})")
            else:
                await msg.edit(content=f"Error: {e.message}")
    except Exception as e:
        await msg.edit(content=f"❌ Error: {str(e)}")

@bot.command()
@commands.cooldown(1, 60, commands.BucketType.user)
async def scanurl(ctx, url: str):
    if not url.startswith(('http://', 'https://')):
        await ctx.send("Please use a valid URL starting with http:// or https://")
        return

    try:
        msg = await ctx.send("Scanning URL...")

        # Generate URL ID
        url_hash = hashlib.sha256(url.encode()).digest()
        url_id = base64.urlsafe_b64encode(url_hash).decode().strip('=')

        try:
            url_report = await vt_client.get_object_async(f"/urls/{url_id}")
            stats = url_report.last_analysis_stats
            result = (
                f"**Scan results for {url}**\n"
                f"✅ **Malicious**: {stats.get('malicious', 0)}\n"
                f"✅ **Undetected**: {stats.get('undetected', 0)}\n"
                f"🔗 [View on VirusTotal]({url_report.url})"
            )
            await msg.edit(content=result)
        except vt.APIError as e:
            if e.code == 'NotFoundError':
                await msg.edit(content="Submitting URL for analysis...")
                analysis = await vt_client.scan_url_async(url)
                analysis_url = f"https://www.virustotal.com/gui/analysis/{analysis.id}"
                await msg.edit(content=f"Analysis submitted!\n🔗 [View results]({analysis_url})")
            else:
                await msg.edit(content=f"Error: {e.message}")
    except Exception as e:
        await msg.edit(content=f"❌ Error: {str(e)}")

@scanfile.error
@scanurl.error
async def command_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"Please wait {error.retry_after:.0f} seconds before using this command again.")
    else:
        await ctx.send(f"An error occurred: {str(error)}")

# Slash Commands
@bot.tree.command(name="scan", description="Scan a URL for malware")
@app_commands.describe(url="The URL to scan")
async def scan_url_slash(interaction: discord.Interaction, url: str):
    if not url.startswith(('http://', 'https://')):
        await interaction.response.send_message("Please use a valid URL starting with http:// or https://")
        return

    try:
        await interaction.response.send_message("Scanning URL...")
        
        # Generate URL ID
        url_hash = hashlib.sha256(url.encode()).digest()
        url_id = base64.urlsafe_b64encode(url_hash).decode().strip('=')

        try:
            url_report = await vt_client.get_object_async(f"/urls/{url_id}")
            stats = url_report.last_analysis_stats
            result = (
                f"**Scan results for {url}**\n"
                f"✅ **Malicious**: {stats.get('malicious', 0)}\n"
                f"✅ **Undetected**: {stats.get('undetected', 0)}\n"
                f"🔗 [View on VirusTotal]({url_report.url})"
            )
            await interaction.edit_original_response(content=result)
        except vt.APIError as e:
            if e.code == 'NotFoundError':
                await interaction.edit_original_response(content="Submitting URL for analysis...")
                analysis = await vt_client.scan_url_async(url)
                analysis_url = f"https://www.virustotal.com/gui/analysis/{analysis.id}"
                await interaction.edit_original_response(content=f"Analysis submitted!\n🔗 [View results]({analysis_url})")
            else:
                await interaction.edit_original_response(content=f"Error: {e.message}")
    except Exception as e:
        await interaction.edit_original_response(content=f"❌ Error: {str(e)}")

@bot.tree.command(name="scanfile", description="Scan an attached file for malware")
async def scan_file_slash(interaction: discord.Interaction):
    await interaction.response.send_message("Please use the `/scan` command with a URL or the `!scanfile` command with an attachment.")

bot.run(TOKEN)