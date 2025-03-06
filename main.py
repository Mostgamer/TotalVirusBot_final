import discord
from discord import app_commands
from discord.ext import commands
import os
import hashlib
import base64
from dotenv import load_dotenv
import vt
import aiohttp

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

        # Generate URL ID - correctly encode the URL for VirusTotal API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        print(f"[DEBUG] Generated URL ID: {url_id} for {url}")

        # Use direct HTTP request instead of vt client to avoid timeout issues
        print(f"[INFO] Attempting to get URL report for {url}")

        headers = {"x-apikey": VT_API_KEY}
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        # Create timeout for requests
        timeout = aiohttp.ClientTimeout(total=30)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(vt_url, headers=headers, raise_for_status=False) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data["data"]["attributes"]["last_analysis_stats"]
                        print(f"[SUCCESS] Got URL report. Stats: {stats}")

                        # Create an embed with the scan results
                        embed = discord.Embed(
                            title=f"Scan results for {url}",
                            color=0x66AA33 if stats.get('malicious', 0) == 0 else 0xAA3333
                        )

                        # Add fields with scan statistics
                        embed.add_field(name="Malicious", value=str(stats.get('malicious', 0)), inline=True)
                        embed.add_field(name="Suspicious", value=str(stats.get('suspicious', 0)), inline=True)
                        embed.add_field(name="Undetected", value=str(stats.get('undetected', 0)), inline=True)
                        embed.add_field(name="Harmless", value=str(stats.get('harmless', 0)), inline=True)

                        # Set footer with VirusTotal link and icon
                        embed.set_footer(
                            text="🦠 Results",
                            icon_url="https://www.virustotal.com/gui/images/favicon.png"
                        )

                        # Add VirusTotal URL to the embed
                        vt_url = f"https://www.virustotal.com/gui/url/{url_id}"
                        embed.url = vt_url

                        # Send the embed
                        await interaction.followup.send(embed=embed)
                        print(f"[RESPONSE] Sent URL scan results to {interaction.user.name}")
                    elif response.status == 404:
                        print(f"[INFO] URL not found, submitting for analysis: {url}")
                        await interaction.followup.send("Submitting URL for analysis...")

                        # Submit URL for scanning
                        form_data = aiohttp.FormData()
                        form_data.add_field('url', url)

                        async with session.post(
                            "https://www.virustotal.com/api/v3/urls",
                            data=form_data,
                            headers=headers,
                            raise_for_status=False
                        ) as scan_response:
                            if scan_response.status == 200:
                                scan_data = await scan_response.json()
                                analysis_id = scan_data["data"]["id"]
                                analysis_url = f"https://www.virustotal.com/gui/url/{url_id}/detection"

                                # Create an embed for submission
                                embed = discord.Embed(
                                    title="Analysis submitted!",
                                    description="The URL has been submitted for analysis.",
                                    color=0x3366FF,
                                    url=analysis_url
                                )

                                # Set footer with VirusTotal link and icon
                                embed.set_footer(
                                    text="View on VirusTotal",
                                    icon_url="https://www.virustotal.com/gui/images/favicon.png"
                                )

                                await interaction.followup.send(embed=embed)
                                print(f"[SUCCESS] URL submitted for analysis. Analysis ID: {analysis_id}")
                            else:
                                error_text = await scan_response.text()
                                await interaction.followup.send(f"Error submitting URL: {error_text}")
                                print(f"[ERROR] Failed to submit URL: {error_text}")
                    else:
                        error_text = await response.text()
                        await interaction.followup.send(f"Error: {error_text}")
                        print(f"[ERROR] Failed to get URL report: {error_text}")
        except discord.NotFound as e:
            print(f"[ERROR] Interaction not found: {str(e)}")
        except aiohttp.ClientError as e:
            print(f"[ERROR] HTTP request error: {str(e)}")
            try:
                await interaction.followup.send(f"Error connecting to VirusTotal: {str(e)}")
            except discord.NotFound:
                pass
        except Exception as e:
            print(f"[ERROR] Failed to handle URL scan: {str(e)}")
            try:
                await interaction.followup.send(f"Error: {str(e)}")
            except discord.NotFound:
                pass
    except Exception as e:
        print(f"[EXCEPTION] Unhandled error during URL scan: {str(e)}")
        try:
            await interaction.followup.send(f"❌ Error: {str(e)}")
        except discord.NotFound:
            pass

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
            # Use direct HTTP request instead of vt client to avoid timeout issues
            print(f"[INFO] Attempting to get file report for {file.filename}")

            # Create session and make request manually
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": VT_API_KEY}
                vt_url = f"https://www.virustotal.com/api/v3/files/{sha256}"

                async with session.get(vt_url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data["data"]["attributes"]["last_analysis_stats"]
                        print(f"[SUCCESS] Got file report. Stats: {stats}")

                        # Create an embed with the scan results
                        embed = discord.Embed(
                            title=f"Scan results for {file.filename}",
                            color=0x66AA33 if stats.get('malicious', 0) == 0 else 0xAA3333
                        )

                        # Add fields with scan statistics
                        embed.add_field(name="Malicious", value=str(stats.get('malicious', 0)), inline=True)
                        embed.add_field(name="Suspicious", value=str(stats.get('suspicious', 0)), inline=True)
                        embed.add_field(name="Undetected", value=str(stats.get('undetected', 0)), inline=True)
                        embed.add_field(name="Harmless", value=str(stats.get('harmless', 0)), inline=True)

                        # Set footer with VirusTotal link and icon
                        embed.set_footer(
                            text="🦠 Results",
                            icon_url="https://www.virustotal.com/gui/images/favicon.png"
                        )

                        # Add VirusTotal URL to the embed
                        vt_url = f"https://www.virustotal.com/gui/file/{sha256}"
                        embed.url = vt_url

                        # Send the embed
                        await interaction.followup.send(embed=embed)
                        print(f"[RESPONSE] Sent file scan results to {interaction.user.name}")
                    elif response.status == 404:
                        print(f"[INFO] File not found, submitting for analysis: {file.filename}")
                        await interaction.followup.send("Submitting file for analysis...")

                        # Submit file for scanning
                        form_data = aiohttp.FormData()
                        form_data.add_field('file', file_content, filename=file.filename)

                        async with session.post(
                            "https://www.virustotal.com/api/v3/files",
                            data=form_data,
                            headers=headers
                        ) as scan_response:
                            if scan_response.status == 200:
                                scan_data = await scan_response.json()
                                analysis_id = scan_data["data"]["id"]
                                analysis_url = f"https://www.virustotal.com/gui/file/{sha256}/detection"

                                # Create an embed for submission
                                embed = discord.Embed(
                                    title="Analysis submitted!",
                                    description="The file has been submitted for analysis.",
                                    color=0x3366FF,
                                    url=analysis_url
                                )

                                # Set footer with VirusTotal link and icon
                                embed.set_footer(
                                    text="View on VirusTotal",
                                    icon_url="https://www.virustotal.com/gui/images/favicon.png"
                                )

                                await interaction.followup.send(embed=embed)
                                print(f"[SUCCESS] File submitted for analysis. Analysis ID: {analysis_id}")
                            else:
                                error_text = await scan_response.text()
                                await interaction.followup.send(f"Error submitting file: {error_text}")
                                print(f"[ERROR] Failed to submit file: {error_text}")
                    else:
                        error_text = await response.text()
                        await interaction.followup.send(f"Error: {error_text}")
                        print(f"[ERROR] Failed to get file report: {error_text}")
        except Exception as e:
            await interaction.followup.send(f"Error: {str(e)}")
            print(f"[ERROR] Failed to handle file scan: {str(e)}")
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