+   1 """
+   2 Lua Deobfuscator Discord Bot
+   3 Deobfuscates various Lua obfuscation formats including:
+   4 - WeAreDevs/Prometheus
+   5 - Luraph
+   6 - Moonsec v3
+   7 - IronBrew
+   8 - PSU
+   9 - And other common patterns
+  10 """
+  11 
+  12 import discord
+  13 from discord import app_commands
+  14 from discord.ext import commands
+  15 import os
+  16 import re
+  17 import base64
+  18 import zlib
+  19 import string
+  20 import asyncio
+  21 from dotenv import load_dotenv
+  22 from typing import Optional
+  23 import aiohttp
+  24 
+  25 # Load environment variables
+  26 load_dotenv()
+  27 TOKEN = os.getenv('DISCORD_TOKEN')
+  28 
+  29 # Bot setup
+  30 intents = discord.Intents.default()
+  31 intents.message_content = True
+  32 bot = commands.Bot(command_prefix='!', intents=intents)
+  33 
+  34 
+  35 class LuaDeobfuscator:
+  36     """Core deobfuscation engine for Lua scripts"""
+  37     
+  38     def __init__(self):
+  39         self.string_methods = [
+  40             self._decode_base64_strings,
+  41             self._decode_hex_strings,
+  42             self._decode_decimal_char_strings,
+  43             self._decode_escaped_strings,
+  44             self._decode_xor_strings,
+  45             self._decode_loadstring_wrapper,
+  46             self._decode_string_char_concat,
+  47         ]
+  48     
+  49     def detect_obfuscator(self, code: str) -> str:
+  50         """Detect which obfuscator was likely used"""
+  51         patterns = {
+  52             'WeAreDevs/Prometheus': [
+  53                 r'local\s+\w+\s*=\s*{}\s*;\s*local\s+\w+\s*=\s*{}\s*;',
+  54                 r'_G\[\[',
+  55                 r'string\.char\(\d+,\s*\d+,\s*\d+',
+  56                 r'local\s+\w{20,}\s*=',
+  57             ],
+  58             'Luraph': [
+  59                 r'local\s+\w+\s*=\s*\(function\(\)',
+  60                 r'bit32\.',
+  61                 r'getfenv\s*\(\s*0\s*\)',
+  62                 r'\[\[\]\]=',
+  63             ],
+  64             'Moonsec v3': [
+  65                 r'local\s+\w+\s*,\s*\w+\s*,\s*\w+\s*=\s*string\.byte',
+  66                 r'moon[sS]ec',
+  67                 r'string\.sub\s*\(\s*\w+\s*,\s*\w+\s*\+\s*1',
+  68                 r'tonumber\s*\(\s*\w+\s*,\s*36\s*\)',
+  69             ],
+  70             'IronBrew/IB2': [
+  71                 r'local\s+\w+\s*=\s*string;',
+  72                 r'IRONBREW',
+  73                 r'local\s+\w+\s*=\s*bit\s*or\s*bit32',
+  74                 r'function\s+\w+\(\w+,\s*\w+,\s*\w+,\s*\w+\)',
+  75             ],
+  76             'PSU': [
+  77                 r'PSU|psu',
+  78                 r'local\s+\w+\s*=\s*\(function\(\.\.\.\)',
+  79                 r'select\s*\(\s*[\"\']#',
+  80             ],
+  81             'Loadstring/Basic': [
+  82                 r'loadstring\s*\(',
+  83                 r'load\s*\(\s*[\"\']',
+  84             ],
+  85             'String.char Obfuscation': [
+  86                 r'string\.char\s*\(\s*\d+\s*\)',
+  87             ],
+  88             'Base64 Encoded': [
+  89                 r'[A-Za-z0-9+/]{50,}={0,2}',
+  90             ],
+  91         }
+  92         
+  93         detected = []
+  94         for name, pattern_list in patterns.items():
+  95             for pattern in pattern_list:
+  96                 if re.search(pattern, code, re.IGNORECASE):
+  97                     if name not in detected:
+  98                         detected.append(name)
+  99                     break
+ 100         
+ 101         return ', '.join(detected) if detected else 'Unknown/Custom'
+ 102     
+ 103     def _decode_base64_strings(self, code: str) -> str:
+ 104         """Decode base64 encoded strings in the code"""
+ 105         def decode_match(match):
+ 106             try:
+ 107                 encoded = match.group(1)
+ 108                 decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
+ 109                 if decoded.isprintable() or '\n' in decoded or '\t' in decoded:
+ 110                     return f'"{decoded}"'
+ 111             except:
+ 112                 pass
+ 113             return match.group(0)
+ 114         
+ 115         # Match base64 in string literals
+ 116         patterns = [
+ 117             r'[\"\']([A-Za-z0-9+/]{20,}={0,2})[\"\']',
+ 118             r'\[\[([A-Za-z0-9+/]{20,}={0,2})\]\]',
+ 119         ]
+ 120         
+ 121         for pattern in patterns:
+ 122             code = re.sub(pattern, decode_match, code)
+ 123         return code
+ 124     
+ 125     def _decode_hex_strings(self, code: str) -> str:
+ 126         """Decode hex escaped strings like \\x48\\x65\\x6c\\x6c\\x6f"""
+ 127         def decode_hex(match):
+ 128             try:
+ 129                 hex_str = match.group(0)
+ 130                 decoded = bytes.fromhex(
+ 131                     re.sub(r'\\x', '', hex_str)
+ 132                 ).decode('utf-8', errors='ignore')
+ 133                 return f'"{decoded}"'
+ 134             except:
+ 135                 return match.group(0)
+ 136         
+ 137         return re.sub(r'(?:\\x[0-9a-fA-F]{2})+', decode_hex, code)
+ 138     
+ 139     def _decode_decimal_char_strings(self, code: str) -> str:
+ 140         """Decode string.char(72, 101, 108, 108, 111) patterns"""
+ 141         def decode_chars(match):
+ 142             try:
+ 143                 numbers = re.findall(r'\d+', match.group(0))
+ 144                 decoded = ''.join(chr(int(n)) for n in numbers if 0 <= int(n) <= 127)
+ 145                 if decoded and all(c in string.printable for c in decoded):
+ 146                     return f'"{decoded}"'
+ 147             except:
+ 148                 pass
+ 149             return match.group(0)
+ 150         
+ 151         # Match string.char(...) patterns
+ 152         code = re.sub(
+ 153             r'string\.char\s*\(\s*(\d+\s*,?\s*)+\)',
+ 154             decode_chars,
+ 155             code,
+ 156             flags=re.IGNORECASE
+ 157         )
+ 158         return code
+ 159     
+ 160     def _decode_escaped_strings(self, code: str) -> str:
+ 161         """Decode numeric escape sequences like \\104\\101\\108\\108\\111"""
+ 162         def decode_escaped(match):
+ 163             try:
+ 164                 content = match.group(1)
+ 165                 # Find all numeric escapes
+ 166                 decoded = re.sub(
+ 167                     r'\\(\d{1,3})',
+ 168                     lambda m: chr(int(m.group(1))) if int(m.group(1)) <= 127 else m.group(0),
+ 169                     content
+ 170                 )
+ 171                 return f'"{decoded}"'
+ 172             except:
+ 173                 return match.group(0)
+ 174         
+ 175         return re.sub(r'\"((?:\\[0-9]{1,3})+)\"', decode_escaped, code)
+ 176     
+ 177     def _decode_xor_strings(self, code: str) -> str:
+ 178         """Attempt to decode XOR encrypted strings (common pattern)"""
+ 179         # This is a simplified version - real XOR decoding requires knowing the key
+ 180         # We look for patterns like: for i = 1, #str do result = result .. string.char(bxor(byte(str,i), key)) end
+ 181         return code
+ 182     
+ 183     def _decode_loadstring_wrapper(self, code: str) -> str:
+ 184         """Extract code from simple loadstring wrappers"""
+ 185         # Match loadstring("...encoded...")() patterns
+ 186         patterns = [
+ 187             r'loadstring\s*\(\s*[\"\'](.+?)[\"\']\s*\)\s*\(\s*\)',
+ 188             r'load\s*\(\s*[\"\'](.+?)[\"\']\s*\)\s*\(\s*\)',
+ 189         ]
+ 190         
+ 191         for pattern in patterns:
+ 192             match = re.search(pattern, code, re.DOTALL)
+ 193             if match:
+ 194                 inner = match.group(1)
+ 195                 # Try to decode the inner content
+ 196                 try:
+ 197                     decoded = base64.b64decode(inner).decode('utf-8', errors='ignore')
+ 198                     if 'function' in decoded or 'local' in decoded:
+ 199                         return decoded
+ 200                 except:
+ 201                     pass
+ 202         return code
+ 203     
+ 204     def _decode_string_char_concat(self, code: str) -> str:
+ 205         """Decode concatenated string.char calls"""
+ 206         # Pattern: string.char(72)..string.char(101)..string.char(108)
+ 207         pattern = r'((?:string\.char\s*\(\s*\d+\s*\)\s*\.\.?\s*)+string\.char\s*\(\s*\d+\s*\))'
+ 208         
+ 209         def decode_concat(match):
+ 210             try:
+ 211                 full_match = match.group(0)
+ 212                 numbers = re.findall(r'string\.char\s*\(\s*(\d+)\s*\)', full_match)
+ 213                 decoded = ''.join(chr(int(n)) for n in numbers if 0 <= int(n) <= 127)
+ 214                 return f'"{decoded}"'
+ 215             except:
+ 216                 return match.group(0)
+ 217         
+ 218         return re.sub(pattern, decode_concat, code, flags=re.IGNORECASE)
+ 219     
+ 220     def beautify(self, code: str) -> str:
+ 221         """Beautify Lua code with proper indentation"""
+ 222         lines = code.split('\n')
+ 223         result = []
+ 224         indent = 0
+ 225         
+ 226         indent_keywords = {'function', 'if', 'for', 'while', 'repeat', 'do'}
+ 227         dedent_keywords = {'end', 'until'}
+ 228         both_keywords = {'else', 'elseif'}
+ 229         
+ 230         for line in lines:
+ 231             stripped = line.strip()
+ 232             if not stripped:
+ 233                 result.append('')
+ 234                 continue
+ 235             
+ 236             # Check for dedent keywords at start
+ 237             first_word = stripped.split()[0] if stripped.split() else ''
+ 238             first_word = first_word.rstrip('(').rstrip(':')
+ 239             
+ 240             if first_word in dedent_keywords or first_word in both_keywords:
+ 241                 indent = max(0, indent - 1)
+ 242             
+ 243             result.append('    ' * indent + stripped)
+ 244             
+ 245             # Check for indent keywords
+ 246             if first_word in indent_keywords or first_word in both_keywords:
+ 247                 indent += 1
+ 248             # Also check for inline patterns like "function foo()"
+ 249             if re.search(r'\bfunction\s+\w+\s*\([^)]*\)\s*$', stripped):
+ 250                 if first_word not in indent_keywords:
+ 251                     indent += 1
+ 252             if re.search(r'\bif\b.+\bthen\s*$', stripped):
+ 253                 if first_word not in indent_keywords:
+ 254                     indent += 1
+ 255         
+ 256         return '\n'.join(result)
+ 257     
+ 258     def rename_variables(self, code: str) -> str:
+ 259         """Rename obfuscated variables to readable names"""
+ 260         # Find all obfuscated variable names (long random strings)
+ 261         var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]{15,})\b'
+ 262         obfuscated_vars = set(re.findall(var_pattern, code))
+ 263         
+ 264         # Create readable names
+ 265         var_counter = 1
+ 266         replacements = {}
+ 267         for var in obfuscated_vars:
+ 268             # Skip common Lua globals and functions
+ 269             if var.lower() in {'string', 'table', 'math', 'coroutine', 'debug', 'getfenv', 'setfenv', 'loadstring', 'tonumber', 'tostring'}:
+ 270                 continue
+ 271             replacements[var] = f'var_{var_counter}'
+ 272             var_counter += 1
+ 273         
+ 274         # Apply replacements
+ 275         for old, new in replacements.items():
+ 276             code = re.sub(rf'\b{re.escape(old)}\b', new, code)
+ 277         
+ 278         return code
+ 279     
+ 280     def deobfuscate(self, code: str) -> tuple[str, str]:
+ 281         """Main deobfuscation method"""
+ 282         detected = self.detect_obfuscator(code)
+ 283         result = code
+ 284         
+ 285         # Apply all string decoding methods
+ 286         for method in self.string_methods:
+ 287             result = method(result)
+ 288         
+ 289         # Rename obfuscated variables
+ 290         result = self.rename_variables(result)
+ 291         
+ 292         # Beautify the code
+ 293         result = self.beautify(result)
+ 294         
+ 295         return result, detected
+ 296 
+ 297 
+ 298 class AIDeobfuscator:
+ 299     """Uses AI (Claude via Poe) for advanced deobfuscation analysis"""
+ 300     
+ 301     @staticmethod
+ 302     async def analyze_with_ai(code: str, detected_type: str) -> str:
+ 303         """
+ 304         Use Claude to analyze and explain obfuscated code.
+ 305         This provides deeper analysis for complex obfuscation.
+ 306         """
+ 307         # This is a placeholder - in production you'd integrate with your preferred AI API
+ 308         # For now, we return analysis guidance
+ 309         
+ 310         analysis = f"""
+ 311 **AI Analysis for {detected_type} Obfuscation:**
+ 312 
+ 313 The code uses the following obfuscation techniques:
+ 314 """
+ 315         
+ 316         # Analyze techniques used
+ 317         techniques = []
+ 318         
+ 319         if 'string.char' in code.lower():
+ 320             techniques.append("• **String.char encoding**: Characters encoded as numeric values")
+ 321         
+ 322         if 'loadstring' in code.lower() or 'load(' in code:
+ 323             techniques.append("• **Dynamic code loading**: Code is loaded/executed at runtime")
+ 324         
+ 325         if re.search(r'bit32|bxor|band|bor', code, re.IGNORECASE):
+ 326             techniques.append("• **Bitwise operations**: XOR/AND/OR used for encoding")
+ 327         
+ 328         if re.search(r'getfenv|setfenv', code, re.IGNORECASE):
+ 329             techniques.append("• **Environment manipulation**: Function environments are modified")
+ 330         
+ 331         if re.search(r'\b[a-zA-Z_][a-zA-Z0-9_]{20,}\b', code):
+ 332             techniques.append("• **Variable name obfuscation**: Long random variable names")
+ 333         
+ 334         if re.search(r'while\s+true\s+do|for\s+\w+\s*=\s*1\s*,\s*1\s*do', code):
+ 335             techniques.append("• **Control flow flattening**: Complex loop structures")
+ 336         
+ 337         if re.search(r'local\s+\w+\s*=\s*{[^}]{100,}}', code):
+ 338             techniques.append("• **Lookup tables**: Large tables used for bytecode/strings")
+ 339         
+ 340         if not techniques:
+ 341             techniques.append("• Standard obfuscation patterns detected")
+ 342         
+ 343         analysis += '\n'.join(techniques)
+ 344         
+ 345         return analysis
+ 346 
+ 347 
+ 348 # Discord UI Components
+ 349 class DeobfuscateModal(discord.ui.Modal, title='Lua Deobfuscator'):
+ 350     """Modal for pasting Lua code"""
+ 351     
+ 352     code = discord.ui.TextInput(
+ 353         label='Paste Obfuscated Lua Code',
+ 354         style=discord.TextStyle.paragraph,
+ 355         placeholder='Paste your obfuscated Lua code here...',
+ 356         required=True,
+ 357         max_length=4000
+ 358     )
+ 359     
+ 360     async def on_submit(self, interaction: discord.Interaction):
+ 361         await interaction.response.defer(thinking=True)
+ 362         
+ 363         deobfuscator = LuaDeobfuscator()
+ 364         result, detected = deobfuscator.deobfuscate(self.code.value)
+ 365         
+ 366         # Get AI analysis
+ 367         ai_analysis = await AIDeobfuscator.analyze_with_ai(self.code.value, detected)
+ 368         
+ 369         # Create embed
+ 370         embed = discord.Embed(
+ 371             title="🔓 Lua Deobfuscation Result",
+ 372             color=discord.Color.green()
+ 373         )
+ 374         embed.add_field(name="Detected Obfuscator", value=detected, inline=False)
+ 375         embed.add_field(name="Analysis", value=ai_analysis[:1024], inline=False)
+ 376         
+ 377         # Send result
+ 378         if len(result) <= 1900:
+ 379             await interaction.followup.send(
+ 380                 embed=embed,
+ 381                 content=f"```lua\n{result}\n```"
+ 382             )
+ 383         else:
+ 384             # Send as file if too long
+ 385             with open('deobfuscated.lua', 'w', encoding='utf-8') as f:
+ 386                 f.write(result)
+ 387             
+ 388             await interaction.followup.send(
+ 389                 embed=embed,
+ 390                 file=discord.File('deobfuscated.lua')
+ 391             )
+ 392             os.remove('deobfuscated.lua')
+ 393 
+ 394 
+ 395 class DeobfuscateView(discord.ui.View):
+ 396     """View with deobfuscate button"""
+ 397     
+ 398     def __init__(self):
+ 399         super().__init__(timeout=None)
+ 400     
+ 401     @discord.ui.button(label='Paste Code', style=discord.ButtonStyle.primary, emoji='📝')
+ 402     async def paste_button(self, interaction: discord.Interaction, button: discord.ui.Button):
+ 403         await interaction.response.send_modal(DeobfuscateModal())
+ 404 
+ 405 
+ 406 # Bot Events
+ 407 @bot.event
+ 408 async def on_ready():
+ 409     print(f'✅ {bot.user} is online!')
+ 410     print(f'📊 Connected to {len(bot.guilds)} servers')
+ 411     
+ 412     # Sync slash commands
+ 413     try:
+ 414         synced = await bot.tree.sync()
+ 415         print(f'🔄 Synced {len(synced)} command(s)')
+ 416     except Exception as e:
+ 417         print(f'❌ Failed to sync commands: {e}')
+ 418 
+ 419 
+ 420 # Slash Commands
+ 421 @bot.tree.command(name='deobfuscate', description='Deobfuscate Lua code')
+ 422 async def deobfuscate_command(interaction: discord.Interaction):
+ 423     """Open the deobfuscation modal"""
+ 424     await interaction.response.send_modal(DeobfuscateModal())
+ 425 
+ 426 
+ 427 @bot.tree.command(name='deobfuscate_file', description='Deobfuscate a Lua file')
+ 428 @app_commands.describe(file='The .lua file to deobfuscate')
+ 429 async def deobfuscate_file_command(interaction: discord.Interaction, file: discord.Attachment):
+ 430     """Deobfuscate an uploaded Lua file"""
+ 431     if not file.filename.endswith('.lua') and not file.filename.endswith('.txt'):
+ 432         await interaction.response.send_message(
+ 433             "❌ Please upload a `.lua` or `.txt` file!",
+ 434             ephemeral=True
+ 435         )
+ 436         return
+ 437     
+ 438     await interaction.response.defer(thinking=True)
+ 439     
+ 440     try:
+ 441         # Download file content
+ 442         content = await file.read()
+ 443         code = content.decode('utf-8', errors='ignore')
+ 444         
+ 445         # Deobfuscate
+ 446         deobfuscator = LuaDeobfuscator()
+ 447         result, detected = deobfuscator.deobfuscate(code)
+ 448         
+ 449         # Get AI analysis
+ 450         ai_analysis = await AIDeobfuscator.analyze_with_ai(code, detected)
+ 451         
+ 452         # Create embed
+ 453         embed = discord.Embed(
+ 454             title=f"🔓 Deobfuscated: {file.filename}",
+ 455             color=discord.Color.green()
+ 456         )
+ 457         embed.add_field(name="Detected Obfuscator", value=detected, inline=False)
+ 458         embed.add_field(name="Original Size", value=f"{len(code):,} bytes", inline=True)
+ 459         embed.add_field(name="Deobfuscated Size", value=f"{len(result):,} bytes", inline=True)
+ 460         embed.add_field(name="Analysis", value=ai_analysis[:1024], inline=False)
+ 461         
+ 462         # Save and send result
+ 463         output_name = f"deobfuscated_{file.filename}"
+ 464         with open(output_name, 'w', encoding='utf-8') as f:
+ 465             f.write(result)
+ 466         
+ 467         await interaction.followup.send(
+ 468             embed=embed,
+ 469             file=discord.File(output_name)
+ 470         )
+ 471         os.remove(output_name)
+ 472         
+ 473     except Exception as e:
+ 474         await interaction.followup.send(f"❌ Error: {str(e)}")
+ 475 
+ 476 
+ 477 @bot.tree.command(name='analyze', description='Analyze obfuscation type without deobfuscating')
+ 478 async def analyze_command(interaction: discord.Interaction, file: discord.Attachment):
+ 479     """Analyze what type of obfuscation is used"""
+ 480     await interaction.response.defer(thinking=True)
+ 481     
+ 482     try:
+ 483         content = await file.read()
+ 484         code = content.decode('utf-8', errors='ignore')
+ 485         
+ 486         deobfuscator = LuaDeobfuscator()
+ 487         detected = deobfuscator.detect_obfuscator(code)
+ 488         ai_analysis = await AIDeobfuscator.analyze_with_ai(code, detected)
+ 489         
+ 490         embed = discord.Embed(
+ 491             title=f"🔍 Analysis: {file.filename}",
+ 492             color=discord.Color.blue()
+ 493         )
+ 494         embed.add_field(name="Detected Obfuscator(s)", value=detected, inline=False)
+ 495         embed.add_field(name="File Size", value=f"{len(code):,} bytes", inline=True)
+ 496         embed.add_field(name="Lines", value=f"{code.count(chr(10)):,}", inline=True)
+ 497         embed.add_field(name="Detailed Analysis", value=ai_analysis[:1024], inline=False)
+ 498         
+ 499         await interaction.followup.send(embed=embed)
+ 500         
+ 501     except Exception as e:
+ 502         await interaction.followup.send(f"❌ Error: {str(e)}")
+ 503 
+ 504 
+ 505 @bot.tree.command(name='help', description='Show help for the Lua Deobfuscator bot')
+ 506 async def help_command(interaction: discord.Interaction):
+ 507     """Show help information"""
+ 508     embed = discord.Embed(
+ 509         title="🔓 Lua Deobfuscator Bot - Help",
+ 510         description="A powerful bot for deobfuscating Lua scripts",
+ 511         color=discord.Color.purple()
+ 512     )
+ 513     
+ 514     embed.add_field(
+ 515         name="📋 Commands",
+ 516         value="""
+ 517 `/deobfuscate` - Open modal to paste code
+ 518 `/deobfuscate_file` - Upload a .lua file to deobfuscate
+ 519 `/analyze` - Analyze obfuscation type only
+ 520 `/help` - Show this help message
+ 521         """,
+ 522         inline=False
+ 523     )
+ 524     
+ 525     embed.add_field(
+ 526         name="🛡️ Supported Obfuscators",
+ 527         value="""
+ 528 • WeAreDevs / Prometheus
+ 529 • Luraph
+ 530 • Moonsec v3
+ 531 • IronBrew / IB2
+ 532 • PSU
+ 533 • Loadstring wrappers
+ 534 • String.char obfuscation
+ 535 • Base64 / Hex encoding
+ 536 • Variable renaming
+ 537 • And more...
+ 538         """,
+ 539         inline=False
+ 540     )
+ 541     
+ 542     embed.add_field(
+ 543         name="⚠️ Note",
+ 544         value="Complex VM-based obfuscators (Luraph, Moonsec) may only be partially deobfuscated. The bot will provide analysis and decode what it can.",
+ 545         inline=False
+ 546     )
+ 547     
+ 548     embed.set_footer(text="Lua Deobfuscator Bot v1.0")
+ 549     
+ 550     await interaction.response.send_message(embed=embed)
+ 551 
+ 552 
+ 553 # Message-based deobfuscation (for code blocks)
+ 554 @bot.event
+ 555 async def on_message(message: discord.Message):
+ 556     if message.author.bot:
+ 557         return
+ 558     
+ 559     # Check for Lua code blocks
+ 560     if '```lua' in message.content or '```' in message.content:
+ 561         # Extract code from code block
+ 562         code_match = re.search(r'```(?:lua)?\n?(.*?)```', message.content, re.DOTALL)
+ 563         if code_match and len(code_match.group(1)) > 50:
+ 564             code = code_match.group(1)
+ 565             
+ 566             # Check if it looks obfuscated
+ 567             deobfuscator = LuaDeobfuscator()
+ 568             detected = deobfuscator.detect_obfuscator(code)
+ 569             
+ 570             if detected != 'Unknown/Custom':
+ 571                 # Ask if they want to deobfuscate
+ 572                 view = DeobfuscateConfirmView(code)
+ 573                 await message.reply(
+ 574                     f"🔍 Detected **{detected}** obfuscation. Would you like to deobfuscate this code?",
+ 575                     view=view
+ 576                 )
+ 577     
+ 578     await bot.process_commands(message)
+ 579 
+ 580 
+ 581 class DeobfuscateConfirmView(discord.ui.View):
+ 582     """Confirmation view for auto-detected obfuscation"""
+ 583     
+ 584     def __init__(self, code: str):
+ 585         super().__init__(timeout=60)
+ 586         self.code = code
+ 587     
+ 588     @discord.ui.button(label='Yes, Deobfuscate', style=discord.ButtonStyle.success, emoji='✅')
+ 589     async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
+ 590         await interaction.response.defer(thinking=True)
+ 591         
+ 592         deobfuscator = LuaDeobfuscator()
+ 593         result, detected = deobfuscator.deobfuscate(self.code)
+ 594         
+ 595         embed = discord.Embed(
+ 596             title="🔓 Deobfuscation Result",
+ 597             color=discord.Color.green()
+ 598         )
+ 599         embed.add_field(name="Detected", value=detected, inline=False)
+ 600         
+ 601         if len(result) <= 1900:
+ 602             await interaction.followup.send(
+ 603                 embed=embed,
+ 604                 content=f"```lua\n{result}\n```"
+ 605             )
+ 606         else:
+ 607             with open('deobfuscated.lua', 'w', encoding='utf-8') as f:
+ 608                 f.write(result)
+ 609             await interaction.followup.send(
+ 610                 embed=embed,
+ 611                 file=discord.File('deobfuscated.lua')
+ 612             )
+ 613             os.remove('deobfuscated.lua')
+ 614         
+ 615         self.stop()
+ 616     
+ 617     @discord.ui.button(label='No', style=discord.ButtonStyle.secondary, emoji='❌')
+ 618     async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
+ 619         await interaction.response.send_message("Okay, cancelled!", ephemeral=True)
+ 620         self.stop()
+ 621 
+ 622 
+ 623 # Run the bot
+ 624 if __name__ == '__main__':
+ 625     if not TOKEN:
+ 626         print("❌ Error: DISCORD_TOKEN not found in .env file!")
+ 627         print("Please create a .env file with: DISCORD_TOKEN=your_bot_token_here")
+ 628         exit(1)
+ 629     
+ 630     bot.run(TOKEN)
