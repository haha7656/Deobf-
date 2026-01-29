+   1 """
+   2 Advanced Lua Deobfuscation Module
+   3 Handles complex obfuscation patterns from various obfuscators
+   4 """
+   5 
+   6 import re
+   7 import base64
+   8 import zlib
+   9 import struct
+  10 from typing import Optional, Tuple, List, Dict
+  11 import string
+  12 
+  13 
+  14 class PrometheusDeobfuscator:
+  15     """
+  16     Deobfuscator for WeAreDevs/Prometheus obfuscated scripts
+  17     Prometheus is open source: https://github.com/prometheus-lua/Prometheus
+  18     """
+  19 
+  20     @staticmethod
+  21     def decode_string_array(code: str) -> str:
+  22         """Decode Prometheus string array pattern"""
+  23         # Prometheus often stores strings in a table and references by index
+  24         # Pattern: local stringTable = {"str1", "str2", ...}
+  25 
+  26         # Find string table definitions
+  27         table_pattern = r'local\s+(\w+)\s*=\s*\{([^}]+)\}'
+  28         matches = re.finditer(table_pattern, code)
+  29 
+  30         for match in matches:
+  31             table_name = match.group(1)
+  32             table_content = match.group(2)
+  33 
+  34             # Extract strings from table
+  35             strings = re.findall(r'["\']([^"\']*)["\']', table_content)
+  36             if len(strings) > 5:  # Likely a string table
+  37                 # Replace table[index] with actual strings
+  38                 for i, s in enumerate(strings):
+  39                     # Lua is 1-indexed
+  40                     code = re.sub(
+  41                         rf'{re.escape(table_name)}\s*\[\s*{i + 1}\s*\]',
+  42                         f'"{s}"',
+  43                         code
+  44                     )
+  45 
+  46         return code
+  47 
+  48     @staticmethod
+  49     def decode_control_flow(code: str) -> str:
+  50         """Simplify Prometheus control flow obfuscation"""
+  51         # Remove dummy while true loops with immediate breaks
+  52         code = re.sub(
+  53             r'while\s+true\s+do\s+([^;]+;)\s*break\s*;?\s*end',
+  54             r'\1',
+  55             code
+  56         )
+  57 
+  58         # Remove redundant if true then blocks
+  59         code = re.sub(
+  60             r'if\s+true\s+then\s*\n?\s*(.+?)\s*end',
+  61             r'\1',
+  62             code,
+  63             flags=re.DOTALL
+  64         )
+  65 
+  66         return code
+  67 
+  68 
+  69 class LuraphDeobfuscator:
+  70     """
+  71     Deobfuscator for Luraph obfuscated scripts
+  72     Luraph uses VM-based obfuscation which is extremely hard to reverse
+  73     This provides partial analysis and string extraction
+  74     """
+  75 
+  76     @staticmethod
+  77     def extract_strings(code: str) -> List[str]:
+  78         """Extract readable strings from Luraph bytecode"""
+  79         strings = []
+  80 
+  81         # Look for string literals in the bytecode table
+  82         string_pattern = r'["\']([A-Za-z0-9_\s.,!?@#$%^&*()+=\[\]{}<>:;/\\-]{3,})["\']'
+  83         matches = re.findall(string_pattern, code)
+  84 
+  85         for match in matches:
+  86             if len(match) > 3 and not match.startswith('\\'):
+  87                 strings.append(match)
+  88 
+  89         return list(set(strings))
+  90 
+  91     @staticmethod
+  92     def decode_vm_strings(code: str) -> str:
+  93         """Attempt to decode VM bytecode strings"""
+  94         # Luraph stores strings encoded in the bytecode table
+  95         # Look for patterns like: local bytecode = "..."
+  96 
+  97         bytecode_pattern = r'local\s+\w+\s*=\s*["\']([A-Za-z0-9+/=]+)["\']'
+  98         matches = re.finditer(bytecode_pattern, code)
+  99 
+ 100         decoded_strings = []
+ 101         for match in matches:
+ 102             try:
+ 103                 decoded = base64.b64decode(match.group(1))
+ 104                 # Try to extract ASCII strings from decoded bytecode
+ 105                 ascii_pattern = rb'[\x20-\x7e]{4,}'
+ 106                 ascii_strings = re.findall(ascii_pattern, decoded)
+ 107                 decoded_strings.extend([s.decode('utf-8', errors='ignore') for s in ascii_strings])
+ 108             except:
+ 109                 pass
+ 110 
+ 111         if decoded_strings:
+ 112             # Add extracted strings as comments
+ 113             comment = "\n--[[ Extracted Strings:\n"
+ 114             for s in decoded_strings[:20]:  # Limit to first 20
+ 115                 comment += f"  {s}\n"
+ 116             comment += "]]\n\n"
+ 117             code = comment + code
+ 118 
+ 119         return code
+ 120 
+ 121 
+ 122 class MoonsecDeobfuscator:
+ 123     """
+ 124     Deobfuscator for Moonsec v3 obfuscated scripts
+ 125     Moonsec uses advanced VM protection similar to Luraph
+ 126     """
+ 127 
+ 128     @staticmethod
+ 129     def decode_base36_strings(code: str) -> str:
+ 130         """Decode base36 encoded strings used by Moonsec"""
+ 131         def decode_base36(match):
+ 132             try:
+ 133                 value = match.group(1)
+ 134                 # tonumber(x, 36) in Lua
+ 135                 decoded_num = int(value, 36)
+ 136                 if 32 <= decoded_num <= 126:
+ 137                     return f'"{chr(decoded_num)}"'
+ 138                 return match.group(0)
+ 139             except:
+ 140                 return match.group(0)
+ 141 
+ 142         return re.sub(r'tonumber\s*\(\s*["\']([a-z0-9]+)["\']\s*,\s*36\s*\)', decode_base36, code)
+ 143 
+ 144     @staticmethod
+ 145     def extract_vm_constants(code: str) -> str:
+ 146         """Extract constants from Moonsec VM table"""
+ 147         # Moonsec stores constants in a large table
+ 148         constants = []
+ 149 
+ 150         # Find large table definitions
+ 151         table_pattern = r'\{([^{}]{500,})\}'
+ 152         matches = re.finditer(table_pattern, code)
+ 153 
+ 154         for match in matches:
+ 155             content = match.group(1)
+ 156             # Extract string constants
+ 157             strings = re.findall(r'["\']([^"\']{2,})["\']', content)
+ 158             constants.extend(strings)
+ 159 
+ 160         if constants:
+ 161             unique_constants = list(set(constants))[:30]
+ 162             comment = "\n--[[ VM Constants Found:\n"
+ 163             for c in unique_constants:
+ 164                 if len(c) > 2 and any(char.isalpha() for char in c):
+ 165                     comment += f"  • {c}\n"
+ 166             comment += "]]\n\n"
+ 167             return comment + code
+ 168 
+ 169         return code
+ 170 
+ 171 
+ 172 class IronBrewDeobfuscator:
+ 173     """
+ 174     Deobfuscator for IronBrew/IB2 obfuscated scripts
+ 175     """
+ 176 
+ 177     @staticmethod
+ 178     def decode_string_xor(code: str) -> str:
+ 179         """Decode IronBrew XOR encoded strings"""
+ 180         # IronBrew uses simple XOR with a key
+ 181         # Pattern: for i=1,#s do r=r..char(bxor(byte(s,i),key)) end
+ 182 
+ 183         # Try common XOR keys
+ 184         common_keys = [0x5A, 0xAA, 0x55, 0xFF, 0x42]
+ 185 
+ 186         encoded_pattern = r'["\']([\\x0-9a-fA-F]+)["\']'
+ 187         matches = re.finditer(encoded_pattern, code)
+ 188 
+ 189         for match in matches:
+ 190             encoded = match.group(1)
+ 191             try:
+ 192                 # Convert hex escapes to bytes
+ 193                 raw = bytes.fromhex(encoded.replace('\\x', ''))
+ 194                 for key in common_keys:
+ 195                     decoded = ''.join(chr(b ^ key) for b in raw)
+ 196                     if all(c in string.printable for c in decoded):
+ 197                         code = code.replace(match.group(0), f'"{decoded}"')
+ 198                         break
+ 199             except:
+ 200                 pass
+ 201 
+ 202         return code
+ 203 
+ 204 
+ 205 class PSUDeobfuscator:
+ 206     """
+ 207     Deobfuscator for PSU obfuscated scripts
+ 208     """
+ 209 
+ 210     @staticmethod
+ 211     def decode_vararg_wrapper(code: str) -> str:
+ 212         """Decode PSU vararg wrapper pattern"""
+ 213         # PSU wraps code in (function(...) ... end)(...)
+ 214         pattern = r'\(\s*function\s*\(\s*\.\.\.\s*\)\s*(.+)\s*end\s*\)\s*\([^)]*\)'
+ 215 
+ 216         match = re.search(pattern, code, re.DOTALL)
+ 217         if match:
+ 218             inner = match.group(1)
+ 219             # Clean up the inner code
+ 220             inner = re.sub(r'local\s+\w+\s*=\s*select\s*\([^)]+\)', '', inner)
+ 221             return inner
+ 222 
+ 223         return code
+ 224 
+ 225 
+ 226 class StringDecoder:
+ 227     """Generic string decoding utilities"""
+ 228 
+ 229     @staticmethod
+ 230     def decode_all_patterns(code: str) -> str:
+ 231         """Apply all string decoding patterns"""
+ 232         decoders = [
+ 233             StringDecoder.decode_base64,
+ 234             StringDecoder.decode_hex_escapes,
+ 235             StringDecoder.decode_octal_escapes,
+ 236             StringDecoder.decode_unicode_escapes,
+ 237             StringDecoder.decode_zlib_compressed,
+ 238             StringDecoder.decode_rot13,
+ 239             StringDecoder.decode_reverse_strings,
+ 240         ]
+ 241 
+ 242         for decoder in decoders:
+ 243             try:
+ 244                 code = decoder(code)
+ 245             except:
+ 246                 pass
+ 247 
+ 248         return code
+ 249 
+ 250     @staticmethod
+ 251     def decode_base64(code: str) -> str:
+ 252         """Decode base64 strings"""
+ 253         def try_decode(match):
+ 254             try:
+ 255                 encoded = match.group(1)
+ 256                 decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
+ 257                 if len(decoded) > 3 and decoded.isprintable():
+ 258                     return f'"{decoded}"'
+ 259             except:
+ 260                 pass
+ 261             return match.group(0)
+ 262 
+ 263         return re.sub(r'["\']([A-Za-z0-9+/]{16,}={0,2})["\']', try_decode, code)
+ 264 
+ 265     @staticmethod
+ 266     def decode_hex_escapes(code: str) -> str:
+ 267         """Decode \\xHH escape sequences"""
+ 268         def decode_hex(match):
+ 269             try:
+ 270                 hex_str = match.group(1)
+ 271                 decoded = bytes.fromhex(hex_str.replace('\\x', '')).decode('utf-8', errors='ignore')
+ 272                 return f'"{decoded}"'
+ 273             except:
+ 274                 return match.group(0)
+ 275 
+ 276         return re.sub(r'["\']((\\x[0-9a-fA-F]{2})+)["\']', decode_hex, code)
+ 277 
+ 278     @staticmethod
+ 279     def decode_octal_escapes(code: str) -> str:
+ 280         """Decode \\NNN octal escape sequences"""
+ 281         def decode_octal(match):
+ 282             try:
+ 283                 content = match.group(1)
+ 284                 decoded = re.sub(
+ 285                     r'\\([0-7]{1,3})',
+ 286                     lambda m: chr(int(m.group(1), 8)),
+ 287                     content
+ 288                 )
+ 289                 return f'"{decoded}"'
+ 290             except:
+ 291                 return match.group(0)
+ 292 
+ 293         return re.sub(r'["\']((\\[0-7]{1,3})+)["\']', decode_octal, code)
+ 294 
+ 295     @staticmethod
+ 296     def decode_unicode_escapes(code: str) -> str:
+ 297         """Decode \\uXXXX unicode escapes"""
+ 298         def decode_unicode(match):
+ 299             try:
+ 300                 content = match.group(1)
+ 301                 decoded = content.encode().decode('unicode_escape')
+ 302                 return f'"{decoded}"'
+ 303             except:
+ 304                 return match.group(0)
+ 305 
+ 306         return re.sub(r'["\']((\\u[0-9a-fA-F]{4})+)["\']', decode_unicode, code)
+ 307 
+ 308     @staticmethod
+ 309     def decode_zlib_compressed(code: str) -> str:
+ 310         """Decode zlib compressed data"""
+ 311         # Look for base64 encoded zlib data
+ 312         pattern = r'["\']([A-Za-z0-9+/]{100,}={0,2})["\']'
+ 313 
+ 314         def try_decompress(match):
+ 315             try:
+ 316                 encoded = match.group(1)
+ 317                 compressed = base64.b64decode(encoded)
+ 318                 decompressed = zlib.decompress(compressed).decode('utf-8', errors='ignore')
+ 319                 if 'function' in decompressed or 'local' in decompressed:
+ 320                     return f'[[{decompressed}]]'
+ 321             except:
+ 322                 pass
+ 323             return match.group(0)
+ 324 
+ 325         return re.sub(pattern, try_decompress, code)
+ 326 
+ 327     @staticmethod
+ 328     def decode_rot13(code: str) -> str:
+ 329         """Decode ROT13 encoded strings (rare but possible)"""
+ 330         # Only apply to suspicious patterns that look like ROT13
+ 331 
+ 332         def rot13(s):
+ 333             result = []
+ 334             for c in s:
+ 335                 if 'a' <= c <= 'z':
+ 336                     result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
+ 337                 elif 'A' <= c <= 'Z':
+ 338                     result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
+ 339                 else:
+ 340                     result.append(c)
+ 341             return ''.join(result)
+ 342 
+ 343         # Don't apply globally - only if explicitly marked
+ 344         return code
+ 345 
+ 346     @staticmethod
+ 347     def decode_reverse_strings(code: str) -> str:
+ 348         """Decode reversed strings (string.reverse pattern)"""
+ 349         pattern = r'string\.reverse\s*\(\s*["\']([^"\']+)["\']\s*\)'
+ 350 
+ 351         def reverse_match(match):
+ 352             return f'"{match.group(1)[::-1]}"'
+ 353 
+ 354         return re.sub(pattern, reverse_match, code)
+ 355 
+ 356 
+ 357 class AdvancedDeobfuscator:
+ 358     """Main class combining all deobfuscation techniques"""
+ 359 
+ 360     def __init__(self):
+ 361         self.prometheus = PrometheusDeobfuscator()
+ 362         self.luraph = LuraphDeobfuscator()
+ 363         self.moonsec = MoonsecDeobfuscator()
+ 364         self.ironbrew = IronBrewDeobfuscator()
+ 365         self.psu = PSUDeobfuscator()
+ 366         self.string_decoder = StringDecoder()
+ 367 
+ 368     def full_deobfuscate(self, code: str, detected_type: str) -> Tuple[str, Dict]:
+ 369         """
+ 370         Perform full deobfuscation with all techniques
+ 371 
+ 372         Returns:
+ 373             Tuple of (deobfuscated_code, metadata_dict)
+ 374         """
+ 375         metadata = {
+ 376             'detected_type': detected_type,
+ 377             'techniques_applied': [],
+ 378             'strings_extracted': [],
+ 379             'warnings': []
+ 380         }
+ 381 
+ 382         original_length = len(code)
+ 383         result = code
+ 384 
+ 385         # Apply string decoding first
+ 386         result = self.string_decoder.decode_all_patterns(result)
+ 387         if result != code:
+ 388             metadata['techniques_applied'].append('String decoding')
+ 389 
+ 390         # Apply type-specific deobfuscation
+ 391         if 'prometheus' in detected_type.lower() or 'wearedevs' in detected_type.lower():
+ 392             result = self.prometheus.decode_string_array(result)
+ 393             result = self.prometheus.decode_control_flow(result)
+ 394             metadata['techniques_applied'].append('Prometheus patterns')
+ 395 
+ 396         if 'luraph' in detected_type.lower():
+ 397             extracted = self.luraph.extract_strings(result)
+ 398             metadata['strings_extracted'].extend(extracted)
+ 399             result = self.luraph.decode_vm_strings(result)
+ 400             metadata['techniques_applied'].append('Luraph VM extraction')
+ 401             metadata['warnings'].append('Luraph VM obfuscation cannot be fully reversed')
+ 402 
+ 403         if 'moonsec' in detected_type.lower():
+ 404             result = self.moonsec.decode_base36_strings(result)
+ 405             result = self.moonsec.extract_vm_constants(result)
+ 406             metadata['techniques_applied'].append('Moonsec patterns')
+ 407             metadata['warnings'].append('Moonsec v3 uses VM protection - partial deobfuscation only')
+ 408 
+ 409         if 'ironbrew' in detected_type.lower() or 'ib2' in detected_type.lower():
+ 410             result = self.ironbrew.decode_string_xor(result)
+ 411             metadata['techniques_applied'].append('IronBrew XOR decoding')
+ 412 
+ 413         if 'psu' in detected_type.lower():
+ 414             result = self.psu.decode_vararg_wrapper(result)
+ 415             metadata['techniques_applied'].append('PSU wrapper removal')
+ 416 
+ 417         # Calculate reduction
+ 418         new_length = len(result)
+ 419         if new_length < original_length:
+ 420             reduction = ((original_length - new_length) / original_length) * 100
+ 421             metadata['size_reduction'] = f'{reduction:.1f}%'
+ 422 
+ 423         return result, metadata
+ 424 
+ 425 
+ 426 def analyze_obfuscation_strength(code: str) -> Dict:
+ 427     """
+ 428     Analyze the strength/complexity of obfuscation
+ 429 
+ 430     Returns a dictionary with analysis results
+ 431     """
+ 432     analysis = {
+ 433         'complexity': 'Unknown',
+ 434         'reversibility': 'Unknown',
+ 435         'techniques_detected': [],
+ 436         'recommendation': ''
+ 437     }
+ 438 
+ 439     # Check for VM-based obfuscation (hardest)
+ 440     vm_indicators = [
+ 441         r'local\s+\w+\s*=\s*{[^}]{1000,}}',  # Large bytecode table
+ 442         r'bit32\.',  # Bit operations for VM
+ 443         r'string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)',  # Bytecode reading
+ 444     ]
+ 445 
+ 446     vm_count = sum(1 for p in vm_indicators if re.search(p, code))
+ 447     if vm_count >= 2:
+ 448         analysis['complexity'] = 'Very High (VM-based)'
+ 449         analysis['reversibility'] = 'Partial only'
+ 450         analysis['techniques_detected'].append('Virtual Machine protection')
+ 451         analysis['recommendation'] = 'Full deobfuscation not possible. String extraction and analysis provided.'
+ 452     elif 'loadstring' in code.lower():
+ 453         analysis['complexity'] = 'Medium (Runtime loading)'
+ 454         analysis['reversibility'] = 'Possible with execution'
+ 455         analysis['techniques_detected'].append('Dynamic code loading')
+ 456         analysis['recommendation'] = 'Code is loaded at runtime. Static analysis limited.'
+ 457     else:
+ 458         analysis['complexity'] = 'Low-Medium (String/Variable obfuscation)'
+ 459         analysis['reversibility'] = 'High'
+ 460         analysis['recommendation'] = 'Standard deobfuscation should work well.'
+ 461 
+ 462     # Detect specific techniques
+ 463     if re.search(r'string\.char\s*\(', code):
+ 464         analysis['techniques_detected'].append('String.char encoding')
+ 465     if re.search(r'\\x[0-9a-fA-F]{2}', code):
+ 466         analysis['techniques_detected'].append('Hex encoding')
+ 467     if re.search(r'\b[a-zA-Z_][a-zA-Z0-9_]{20,}\b', code):
+ 468         analysis['techniques_detected'].append('Variable name obfuscation')
+ 469     if re.search(r'getfenv|setfenv', code, re.IGNORECASE):
+ 470         analysis['techniques_detected'].append('Environment manipulation')
+ 471 
+ 472     return analysis
