using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using static BK7231Flasher.MiscUtils;

namespace BK7231Flasher
{
    public class TuyaConfig
    {
        // thanks to kmnh & Kuba bk7231 tools for figuring out this format
        static readonly string KEY_MASTER = "qwertyuiopasdfgh";
        static readonly int SECTOR_SIZE = 4096;
        static readonly uint MAGIC_FIRST_BLOCK = 0x13579753;
        static readonly uint MAGIC_NEXT_BLOCK = 0x98761234;
        static readonly uint MAGIC_FIRST_BLOCK_OS3 = 0x135726AB;
        // 8721D for RTL8720D devices, 8711AM_4M for WRG1. Not known for W800, ECR6600, RTL8720CM, BK7252...
        static readonly byte[] KEY_PART_1 = Encoding.ASCII.GetBytes("8710_2M");
        static readonly byte[] KEY_PART_2 = Encoding.ASCII.GetBytes("HHRRQbyemofrtytf");
        static readonly byte[] KEY_NULL = DeriveVaultKey(KEY_PART_2, KEY_PART_2);
        static readonly byte[] KEY_PART_1_D = Encoding.ASCII.GetBytes("8721D");
        static readonly byte[] KEY_PART_1_AM = Encoding.ASCII.GetBytes("8711AM_4M");

        const int USUAL_BK7231_MAGIC_POSITION = 2023424;
        const int USUAL_BK_NEW_XR806_MAGIC_POSITION = 2052096;
        const int USUAL_RTLB_XR809_MAGIC_POSITION = 2011136;
        const int USUAL_RTLC_ECR6600_MAGIC_POSITION = 1921024;
        const int USUAL_RTLD_MAGIC_POSITION = 3891200;
        const int USUAL_WBRG1_MAGIC_POSITION = 8220672;
        const int USUAL_T3_MAGIC_POSITION = 3997696;
        const int USUAL_T5_MAGIC_POSITION = 8245248;
        const int USUAL_LN882H_MAGIC_POSITION = 2015232;
        const int USUAL_TR6260_MAGIC_POSITION = 860160;
        const int USUAL_W800_MAGIC_POSITION = 1835008;
        const int USUAL_LN8825_MAGIC_POSITION = 1994752;
        const int USUAL_RTLCM_MAGIC_POSITION = 3633152;
        const int USUAL_BK7252_MAGIC_POSITION = 3764224;

        const int KVHeaderSize = 0x12;

        int magicPosition = -1;
        byte[] descryptedRaw;
        byte[] original;
        Dictionary<string, string> parms = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // --------------------------------------------------------------------
        // JSON-driven mapping structures (load once, used instead of hardcoded switch)
        // The code below uses spec/tuya-spec.json (relative to app directory or working dir).
        // If the file is missing or invalid we fail early (per your request, no fallback).
        // --------------------------------------------------------------------

        class MappingEntry
        {
            public string? search { get; set; }
            public string? role { get; set; }          // may be "VALUEONLY", null, or a real role name
            public string? desc { get; set; }
            public bool? nochan { get; set; }
            public int? channel { get; set; }
            public string? special { get; set; }
            public string? conditional { get; set; }
            public int? group { get; set; }
        }

        class SpecRoot
        {
            public object? meta { get; set; }
            public List<MappingEntry>? mappings { get; set; }
            public Dictionary<string, Dictionary<string, string>>? valueMaps { get; set; }
        }

        static Dictionary<string, MappingEntry> s_keyMap = new Dictionary<string, MappingEntry>(StringComparer.OrdinalIgnoreCase);
        static List<(Regex regex, MappingEntry entry)> s_regexList = new List<(Regex, MappingEntry)>();
        static Dictionary<string, Dictionary<string, string>> s_valueMaps = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        static bool s_mappingsInitialized = false;
        static readonly object s_mapLock = new object();

        static void EnsureMappingsLoaded()
        {
            if (s_mappingsInitialized) return;
            lock (s_mapLock)
            {
                if (s_mappingsInitialized) return;
                s_mappingsInitialized = true;

                // locate spec file
                string baseDir = AppContext.BaseDirectory ?? Directory.GetCurrentDirectory();
                string[] candidates = new[]
                {
                    Path.Combine(baseDir, "spec", "tuya-spec.json"),
                    Path.Combine(baseDir, "tuya-spec.json"),
                    Path.Combine(Directory.GetCurrentDirectory(), "spec", "tuya-spec.json"),
                    Path.Combine(Directory.GetCurrentDirectory(), "tuya-spec.json")
                };

                string specPath = candidates.FirstOrDefault(File.Exists);
                if (specPath == null)
                {
                    var msg = "TuyaConfig: spec/tuya-spec.json not found. Aborting mapping initialization (no fallback allowed).";
                    FormMain.Singleton.addLog(msg + Environment.NewLine, System.Drawing.Color.Orange);
                    throw new FileNotFoundException(msg + " Looked in: " + string.Join("; ", candidates));
                }

                string raw = File.ReadAllText(specPath, Encoding.UTF8);

                SpecRoot specRoot = null;
                // Try parsing while skipping comments if possible
                try
                {
                    var docOpts = new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip };
                    using (var doc = JsonDocument.Parse(raw, docOpts))
                    {
                        var json = doc.RootElement.GetRawText();
                        var jopts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                        specRoot = JsonSerializer.Deserialize<SpecRoot>(json, jopts);
                    }
                }
                catch
                {
                    // fallback: strip comments then parse
                    try
                    {
                        string clean = StripJsonComments(raw);
                        var jopts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                        specRoot = JsonSerializer.Deserialize<SpecRoot>(clean, jopts);
                    }
                    catch (Exception ex)
                    {
                        var msg = $"TuyaConfig: Failed to parse spec/tuya-spec.json: {ex.Message}";
                        FormMain.Singleton.addLog(msg + Environment.NewLine, System.Drawing.Color.Orange);
                        throw new Exception(msg, ex);
                    }
                }

                if (specRoot == null || specRoot.mappings == null)
                {
                    var msg = "TuyaConfig: spec/tuya-spec.json missing mappings section or empty.";
                    FormMain.Singleton.addLog(msg + Environment.NewLine, System.Drawing.Color.Orange);
                    throw new Exception(msg);
                }

                s_keyMap = new Dictionary<string, MappingEntry>(StringComparer.OrdinalIgnoreCase);
                s_regexList = new List<(Regex, MappingEntry)>();
                s_valueMaps = specRoot.valueMaps ?? new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

                foreach (var m in specRoot.mappings)
                {
                    if (m == null || string.IsNullOrWhiteSpace(m.search)) continue;
                    var s = m.search.Trim();

                    if (s.Length >= 2 && s[0] == '/' && s[^1] == '/')
                    {
                        var body = s.Substring(1, s.Length - 2);
                        try
                        {
                            var rx = new Regex(body, RegexOptions.Compiled | RegexOptions.CultureInvariant);
                            s_regexList.Add((rx, m));
                        }
                        catch (Exception ex)
                        {
                            FormMain.Singleton.addLog($"TuyaConfig: invalid regex in spec: {s} -> {ex.Message}" + Environment.NewLine, System.Drawing.Color.Orange);
                            // Do not fall back; skip this mapping only
                        }
                    }
                    else
                    {
                        if (!s_keyMap.ContainsKey(s))
                            s_keyMap[s] = m;
                        else
                        {
                            FormMain.Singleton.addLog($"TuyaConfig: duplicate mapping for key '{s}' in spec; first kept." + Environment.NewLine, System.Drawing.Color.Orange);
                        }
                    }
                }

                // all loaded
            }
        }

        // Simple comment stripper preserving strings (used as fallback)
        static string StripJsonComments(string input)
        {
            var sb = new StringBuilder(input.Length);
            bool inString = false;
            char stringChar = '\0';
            bool escape = false;
            bool inLineComment = false;
            bool inBlockComment = false;

            for (int i = 0; i < input.Length; i++)
            {
                char ch = input[i];
                char next = (i + 1 < input.Length) ? input[i + 1] : '\0';

                if (inLineComment)
                {
                    if (ch == '\n')
                    {
                        inLineComment = false;
                        sb.Append(ch);
                    }
                    continue;
                }

                if (inBlockComment)
                {
                    if (ch == '*' && next == '/')
                    {
                        inBlockComment = false;
                        i++; // skip '/'
                    }
                    continue;
                }

                if (inString)
                {
                    sb.Append(ch);
                    if (!escape && ch == stringChar) inString = false;
                    escape = (!escape && ch == '\\');
                    continue;
                }

                if (ch == '"' || ch == '\'')
                {
                    inString = true;
                    stringChar = ch;
                    sb.Append(ch);
                    continue;
                }

                if (ch == '/' && next == '/')
                {
                    inLineComment = true;
                    i++;
                    continue;
                }

                if (ch == '/' && next == '*')
                {
                    inBlockComment = true;
                    i++;
                    continue;
                }

                sb.Append(ch);
            }
            return sb.ToString();
        }

        // Map role string to PinRole enum or handle aliases (BridgeFWD etc.)
        static bool TryApplyMappingToTemplate(MappingEntry m, string key, string value, OBKConfig? tg, int? channelOverride = null)
        {
            if (m == null) return false;

            if (string.IsNullOrWhiteSpace(m.role) || string.Equals(m.role, "VALUEONLY", StringComparison.OrdinalIgnoreCase))
            {
                // explicitly don't set any pin role
                return false;
            }

            // Try direct enum mapping
            if (Enum.TryParse<PinRole>(m.role, true, out var pr))
            {
                int ch = channelOverride ?? m.channel ?? 0;
                tg?.setPinRole(value, pr);
                tg?.setPinChannel(value, ch);
                return true;
            }

            // Alias mapping - extend as needed
            switch (m.role)
            {
                case "BridgeFWD":
                    tg?.setPinRole(value, PinRole.Rel);
                    tg?.setPinChannel(value, channelOverride ?? m.channel ?? 0);
                    return true;
                case "BridgeREV":
                    tg?.setPinRole(value, PinRole.Rel_n);
                    tg?.setPinChannel(value, channelOverride ?? m.channel ?? 0);
                    return true;
                // add other aliases here if your spec uses names that don't match PinRole enum
                default:
                    FormMain.Singleton.addLog($"TuyaConfig: Unknown role '{m.role}' for key '{key}' in tuya-spec.json. Skipping setPinRole." + Environment.NewLine, System.Drawing.Color.Orange);
                    return false;
            }
        }

        // --------------------------------------------------------------------
        // Remaining original TuyaConfig code (key parsing / vault extraction)
        // Keep unchanged besides the getKeysHumanReadable method which is adapted
        // --------------------------------------------------------------------

        public sealed class KvEntry
        {
            public uint ValueLength;
            public ushort KeyId;
            public ushort ChecksumStored;
            public ushort ChecksumCalculated;
            public bool IsCheckSumCorrect => ChecksumStored == ChecksumCalculated;

            public string Key = "";
            public byte[] Value = Array.Empty<byte>();

            public override string ToString()
                => $"{Key} (len={ValueLength}, valid={IsCheckSumCorrect})";
        }

        static ushort CalcChecksum(byte[] buf, int off, int len)
        {
            ushort sum = 0;
            for (int i = off; i < off + len; i++) sum += buf[i];
            return sum;
        }

        static bool TryParseEntry(byte[] pageData, int entryOffset, out KvEntry entry)
        {
            entry = null!;

            if (entryOffset + KVHeaderSize > pageData.Length)
                return false;

            uint valueLen = ReadU32LE(pageData, entryOffset + 4);

            if (valueLen == 0 || valueLen > pageData.Length)
                return false;

            int totalLength = KVHeaderSize + (int)valueLen;
            if (entryOffset + totalLength > pageData.Length)
                return false;

            var storedChsum = ReadU16LE(pageData, entryOffset);
            var keyId = ReadU16LE(pageData, entryOffset + 8);
            var keyLen = pageData[entryOffset + 0x11];
            var keyOff = 18;
            var valOff = 128;

            int keyPos = entryOffset + keyOff;
            if (keyPos < 0 || keyPos >= pageData.Length)
                return false;

            var keyBytes = new List<byte>();
            for (int i = keyPos; i < keyPos + keyLen; i++)
            {
                byte b = pageData[i];
                if (!(b == 0 || (b >= 0x20 && b <= 0x7E)))
                    return false;
                if (b == 0)
                    break;
                keyBytes.Add(b);
            }

            if (keyBytes.Count == 0)
                return false;

            string key = Encoding.ASCII.GetString(keyBytes.ToArray());

            int valPos = entryOffset + valOff;
            if (valPos < 0 || valPos + valueLen > pageData.Length)
                return false;

            ushort calcChsum = CalcChecksum(pageData, valPos, (int)valueLen);

            byte[] value = new byte[valueLen];
            Buffer.BlockCopy(pageData, valPos, value, 0, (int)valueLen);

            entry = new KvEntry
            {
                ValueLength = valueLen,
                KeyId = keyId,
                Key = key,
                Value = value,
                ChecksumStored = storedChsum,
                ChecksumCalculated = calcChsum
            };

            return true;
        }

        List<KvEntry> ParseVault()
        {
            var entries = new List<KvEntry>();
            byte[] data = descryptedRaw;

            for (int off = 0; off + KVHeaderSize < data.Length; off += 0x80)
            {
                if (TryParseEntry(data, off, out var entry))
                {
                    entries.Add(entry);

                    int nextOffset = off + 0x80;
                    if (nextOffset > off)
                        off = nextOffset - 0x80;
                }
            }

            return entries;
        }

        internal static int getMagicOffset(BKType type) => type switch
        {
            BKType.RTL8710B => USUAL_RTLB_XR809_MAGIC_POSITION,
            BKType.RTL87X0C => USUAL_RTLC_ECR6600_MAGIC_POSITION,
            BKType.RTL8720D => USUAL_RTLD_MAGIC_POSITION,
            BKType.LN882H => USUAL_LN882H_MAGIC_POSITION,
            BKType.BK7236 => USUAL_T3_MAGIC_POSITION,
            BKType.BK7238 => USUAL_BK_NEW_XR806_MAGIC_POSITION,
            BKType.BK7258 => USUAL_T5_MAGIC_POSITION,
            BKType.ECR6600 => USUAL_RTLC_ECR6600_MAGIC_POSITION,
            BKType.LN8825 => USUAL_LN8825_MAGIC_POSITION,
            BKType.TR6260 => USUAL_TR6260_MAGIC_POSITION,
            _ => USUAL_BK7231_MAGIC_POSITION,
        };

        public static int getMagicSize(BKType type) => type switch
        {
            BKType.RTL8710B => 0x200000 - USUAL_RTLB_XR809_MAGIC_POSITION,
            BKType.RTL87X0C => 0x1E5000 - USUAL_RTLC_ECR6600_MAGIC_POSITION,
            BKType.RTL8720D => 0x3FC000 - USUAL_RTLD_MAGIC_POSITION,
            BKType.LN882H => 0x200000 - USUAL_LN882H_MAGIC_POSITION,
            BKType.BK7236 => 0x3E0000 - USUAL_T3_MAGIC_POSITION,
            BKType.BK7238 => 0x200000 - USUAL_BK_NEW_XR806_MAGIC_POSITION,
            BKType.BK7258 => 0x7ED000 - USUAL_T5_MAGIC_POSITION,
            BKType.ECR6600 => 0x1F7000 - USUAL_RTLC_ECR6600_MAGIC_POSITION,
            BKType.LN8825 => 0x200000 - USUAL_LN8825_MAGIC_POSITION,
            BKType.TR6260 => 0x0DE000 - USUAL_TR6260_MAGIC_POSITION,
            _ => 0x200000 - USUAL_BK7231_MAGIC_POSITION,
        };

        public string getMagicPositionHex() => $"0x{magicPosition:X}";

        public string getMagicPositionDecAndHex() => $"{magicPosition} ({getMagicPositionHex()})";

        public bool fromFile(string fname)
        {
            using var fs = new FileStream(fname, FileMode.Open, FileAccess.Read);
            var buffer = new byte[fs.Length];
            fs.Read(buffer, 0, buffer.Length);
            return fromBytes(buffer);
        }

        bool bLastBinaryOBKConfig;
        bool bGivenBinaryIsFullOf0xff;
        // warn users that they have erased flash sector with cfg
        public bool isLastBinaryFullOf0xff()
        {
            return bGivenBinaryIsFullOf0xff;
        }
        public bool isLastBinaryOBKConfig()
        {
            return bLastBinaryOBKConfig;
        }

        public bool fromBytes(byte[] data)
        {
            descryptedRaw = null;
            original = data;
            if (isFullOf(data, 0xff))
            {
                FormMain.Singleton.addLog("It seems that dragged binary is full of 0xff, someone must have erased the flash" + Environment.NewLine, System.Drawing.Color.Purple);
                bGivenBinaryIsFullOf0xff = true;
                return true;
            }
            if (data.Length > 3 && data[0] == (byte)'C' && data[1] == (byte)'F' && data[2] == (byte)'G')
            {
                FormMain.Singleton.addLog("It seems that dragged binary is OBK config, not a Tuya one" + Environment.NewLine, System.Drawing.Color.Purple);
                bLastBinaryOBKConfig = true;
                return true;
            }

            try
            {
                if (TryVaultExtract(data)) return false;
            }
            finally
            {
                if (descryptedRaw != null)
                {
                    string debugName = "lastRawDecryptedStrings.bin";
                    FormMain.Singleton.addLog("Saving debug Tuya decryption data to " + debugName + Environment.NewLine, System.Drawing.Color.DarkSlateGray);

                    File.WriteAllBytes(debugName, descryptedRaw);
                }
            }

            return true;
        }

        bool TryVaultExtract(byte[] flash)
        {
            descryptedRaw = null;

            var deviceKeys = FindDeviceKeys(flash);
            if (deviceKeys.Count == 0)
            {
                FormMain.Singleton.addLog("Failed to extract Tuya keys - magic constant header not found in binary" + Environment.NewLine, System.Drawing.Color.Purple);
                return false;
            }

            var baseKeyCandidates = new byte[][]
            {
                KEY_PART_1,
                KEY_NULL,
                KEY_PART_1_D,
                KEY_PART_2,
                KEY_PART_1_AM,
            };

            var pageMagics = new uint[] { MAGIC_NEXT_BLOCK, MAGIC_FIRST_BLOCK_OS3, MAGIC_FIRST_BLOCK };

            List<VaultPage> bestPages = null;
            int bestCount = 0;
            var obj = new object();
            var time = Stopwatch.StartNew();
            foreach (var devKey in deviceKeys)
            {
                Parallel.ForEach(baseKeyCandidates, baseKey =>
                {
                    using var aes = Aes.Create();
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;
                    aes.KeySize = 128;
                    aes.Key = DeriveVaultKey(devKey, baseKey);
                    using var decryptor = aes.CreateDecryptor();
                    var blockBuffer = new byte[SECTOR_SIZE];
                    var firstBlock = new byte[16];
                    foreach (var magic in pageMagics)
                    {
                        List<VaultPage> pages = new List<VaultPage>();

                        for (int ofs = 0; ofs + SECTOR_SIZE <= flash.Length; ofs += SECTOR_SIZE)
                        {
                            decryptor.TransformBlock(flash, ofs, 16, firstBlock, 0);

                            var pageMagic = ReadU32LE(firstBlock, 0);
                            if (pageMagic != magic) continue;

                            var dec = AESDecrypt(flash, ofs, decryptor, blockBuffer);

                            if (dec == null) continue;

                            var crc = ReadU32LE(dec, 4);
                            if (!checkCRC(crc, dec, 8, dec.Length - 8))
                            {
                                FormMain.Singleton.addLog($"WARNING - bad block CRC at offset {ofs}" + Environment.NewLine, System.Drawing.Color.Purple);
                                continue;
                            }

                            var seq = ReadU32LE(dec, 8);

                            pages.Add(new VaultPage
                            {
                                FlashOffset = ofs,
                                Seq = seq,
                                Data = dec
                            });
                        }
                        lock (obj)
                        {
                            if (pages.Count > bestCount)
                            {
                                bestCount = pages.Count;
                                bestPages = pages;
                            }
                        }
                    }
                });
            }
            time.Stop();
            if (bestPages == null)
            {
                FormMain.Singleton.addLog("Failed to extract Tuya keys - decryption failed" + Environment.NewLine, System.Drawing.Color.Orange);
                return false;
            }
            FormMain.Singleton.addLog($"Decryption took {time.ElapsedMilliseconds} ms" + Environment.NewLine, System.Drawing.Color.DarkSlateGray);

            var dataFlashOffset = bestPages.Min(x => x.FlashOffset);
            magicPosition = magicPosition < dataFlashOffset ? magicPosition : dataFlashOffset;
            FormMain.Singleton.addLog($"Tuya config extractor - magic is at {magicPosition} (0x{magicPosition:X}) " + Environment.NewLine, System.Drawing.Color.DarkSlateGray);

            if (bestPages.Count < 2)
            {
                FormMain.Singleton.addLog("Failed to extract Tuya keys - config not found" + Environment.NewLine, System.Drawing.Color.Orange);
                return false;
            }

            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);
            foreach (var p in bestPages) bw.Write(p.Data, 0, p.Data.Length);

            descryptedRaw = ms.ToArray();
            return true;
        }

        static byte[] DeriveVaultKey(byte[] baseKey, byte[] deviceKey)
        {
            if (baseKey.Length != 16)
                throw new Exception($"baseKey.Length != 16 ({baseKey.Length}");
            var vaultKey = new byte[16];
            if (deviceKey.Length != 16)
            {
                for (int i = 0; i < 16; i++)
                {
                    int v = deviceKey[i & 3] + KEY_PART_2[i];
                    vaultKey[i] = (byte)((v + baseKey[i]) & 0xFF);
                }
                return vaultKey;
            }
            for (int i = 0; i < 16; i++) vaultKey[i] = (byte)((baseKey[i] + deviceKey[i]) & 0xFF);
            return vaultKey;
        }

        List<byte[]> FindDeviceKeys(byte[] flash)
        {
            var keys = new List<byte[]>();
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            aes.Key = Encoding.ASCII.GetBytes(KEY_MASTER);

            using var decryptor = aes.CreateDecryptor();
            var blockBuffer = new byte[SECTOR_SIZE];
            var dec = new byte[16];
            for (int ofs = 0; ofs + SECTOR_SIZE <= flash.Length; ofs += SECTOR_SIZE)
            {
                decryptor.TransformBlock(flash, ofs, 16, dec, 0);

                var pageMagic = ReadU32LE(dec, 0);
                if (pageMagic != MAGIC_FIRST_BLOCK) continue;

                dec = AESDecrypt(flash, ofs, decryptor, blockBuffer);
                if (dec == null) continue;

                var dk = new byte[16];
                Array.Copy(dec, 8, dk, 0, 16);

                var crc = ReadU32LE(dec, 4);
                if (checkCRC(crc, dk, 0, 16))
                {
                    keys.Add(dk);
                    magicPosition = ofs;
                }
            }
            return keys;
        }

        byte[] AESDecrypt(byte[] flash, int ofs, ICryptoTransform decryptor, byte[] buffer)
        {
            Array.Copy(flash, ofs, buffer, 0, SECTOR_SIZE);
            return decryptor.TransformFinalBlock(buffer, 0, SECTOR_SIZE);
        }

        // New JSON-driven getKeysHumanReadable
        public string getKeysHumanReadable(OBKConfig tg = null)
        {
            EnsureMappingsLoaded();

            var descSb = new StringBuilder();
            bool any = false;

            // We only produce lines for keys matched in the spec (no internal fallback)
            foreach (var kv in parms)
            {
                string key = kv.Key;
                string value = kv.Value;

                MappingEntry mapping = null;

                // exact key
                if (s_keyMap.TryGetValue(key, out var mExact))
                {
                    mapping = mExact;
                }
                else
                {
                    // regex
                    foreach (var (rx, me) in s_regexList)
                    {
                        var mm = rx.Match(key);
                        if (!mm.Success) continue;
                        // copy mapping so we can compute channel from group if needed
                        mapping = me;
                        // determine number/group and place into m.channel temporarily via a local
                        int? number = null;
                        if (mapping.group.HasValue)
                        {
                            int g = mapping.group.Value;
                            if (g >= 0 && g < mm.Groups.Count)
                            {
                                var raw = mm.Groups[g].Value;
                                if (!string.IsNullOrEmpty(raw) && int.TryParse(raw, out var n)) number = n;
                            }
                        }
                        else if (mm.Groups.Count > 1)
                        {
                            var raw = mm.Groups[1].Value;
                            if (!string.IsNullOrEmpty(raw) && int.TryParse(raw, out var n)) number = n;
                        }

                        // Build description and apply mapping using number if present
                        string line = (mapping.desc ?? "").Replace("{value}", value).Replace("{number}", number.HasValue ? number.Value.ToString() : "");
                        descSb.AppendLine(line);
                        any = true;

                        // apply mapping (use number as override for channel if present)
                        TryApplyMappingToTemplate(mapping, key, value, tg, number);
                        // stop at first matching regex
                        mapping = null; // we've already processed it
                        break;
                    }
                }

                // if exact mapping found, handle it
                if (mapping != null)
                {
                    // value maps (human readable)
                    if (!string.IsNullOrEmpty(mapping.role) && string.Equals(mapping.role, "VALUEONLY", StringComparison.OrdinalIgnoreCase))
                    {
                        // produce description with value and optionally map via valueMaps
                        string human = value;
                        if (s_valueMaps != null && s_valueMaps.TryGetValue(key, out var vm))
                        {
                            if (vm.TryGetValue(value ?? "", out var mapped)) human = $"{value} ({mapped})";
                            else
                            {
                                var possible = string.Join(", ", vm.Select(kv2 => $"{kv2.Key}={kv2.Value}"));
                                human = $"{value} (Unknown). Known: {possible}";
                            }
                        }
                        string line = (mapping.desc ?? "").Replace("{value}", human).Replace("{number}", mapping.channel.HasValue ? mapping.channel.Value.ToString() : "");
                        descSb.AppendLine(line);
                        any = true;
                        // do not apply pin role for VALUEONLY
                    }
                    else
                    {
                        string line = (mapping.desc ?? "").Replace("{value}", value).Replace("{number}", mapping.channel.HasValue ? mapping.channel.Value.ToString() : "");
                        descSb.AppendLine(line);
                        any = true;
                        TryApplyMappingToTemplate(mapping, key, value, tg);
                    }
                }
            }

            // Special: run I2C LED detection block if the parsed keys indicate it.
            // Many mappings for i2c are marked with special:"i2c" in the spec; here we detect iicscl/iicsda keys.
            string iicscl = getKeyValue("iicscl");
            string iicsda = getKeyValue("iicsda");
            if (string.IsNullOrEmpty(iicscl)) iicscl = getKeyValue("i2c_scl_pin");
            if (string.IsNullOrEmpty(iicsda)) iicsda = getKeyValue("i2c_sda_pin");

            if (!string.IsNullOrEmpty(iicscl) && !string.IsNullOrEmpty(iicsda))
            {
                // replicate earlier LED-detection logic, reading currents etc.
                string iicr = getKeyValue("iicr", "-1");
                string iicg = getKeyValue("iicg", "-1");
                string iicb = getKeyValue("iicb", "-1");
                string iicc = getKeyValue("iicc", "-1");
                string iicw = getKeyValue("iicw", "-1");
                string ledType = "Unknown";
                string iicccur = getKeyValue("iicccur");
                string iicwcur = getKeyValue("iicwcur");
                string campere = getKeyValue("campere");
                string wampere = getKeyValue("wampere");
                string ehccur = getKeyValue("ehccur");
                string ehwcur = getKeyValue("ehwcur");
                string drgbcur = getKeyValue("drgbcur");
                string dwcur = getKeyValue("dwcur");
                string dccur = getKeyValue("dccur");
                string cjwcur = getKeyValue("cjwcur");
                string cjccur = getKeyValue("cjccur");
                string _2235ccur = getKeyValue("2235ccur");
                string _2235wcur = getKeyValue("2235wcur");
                string kp58wcur = getKeyValue("kp58wcur");
                string kp58ccur = getKeyValue("kp58ccur");
                string currents = string.Empty;
                bool isExc = false;

                if (ehccur.Length > 0 || wampere.Length > 0 || iicccur.Length > 0)
                {
                    ledType = "SM2135";
                    var rgbcurrent = 1;
                    var cwcurrent = 1;
                    try
                    {
                        rgbcurrent = ehccur.Length > 0 ? Convert.ToInt32(ehccur) : iicccur.Length > 0 ? Convert.ToInt32(iicccur) : campere.Length > 0 ? Convert.ToInt32(campere) : 1;
                        cwcurrent = ehwcur.Length > 0 ? Convert.ToInt32(ehwcur) : iicwcur.Length > 0 ? Convert.ToInt32(iicwcur) : wampere.Length > 0 ? Convert.ToInt32(wampere) : 1;
                    }
                    catch
                    {
                        isExc = true;
                    }
                    finally
                    {
                        if (tg != null && !isExc) tg.initCommandLine += $"SM2135_Current {rgbcurrent} {cwcurrent}\r\n";
                    }
                    currents = $"- RGB current is {(ehccur.Length > 0 ? ehccur : iicccur.Length > 0 ? iicccur : campere.Length > 0 ? campere : "Unknown")} mA" + Environment.NewLine;
                    currents += $"- White current is {(ehwcur.Length > 0 ? ehwcur : iicwcur.Length > 0 ? iicwcur : wampere.Length > 0 ? wampere : "Unknown")} mA" + Environment.NewLine;
                    tg?.setPinRole(iicsda, PinRole.SM2135DAT);
                    tg?.setPinRole(iicscl, PinRole.SM2135CLK);
                }
                else if (dccur.Length > 0)
                {
                    ledType = "BP5758D_";
                    var rgbcurrent = 1;
                    var wcurrent = 1;
                    var ccurrent = 1;
                    try
                    {
                        rgbcurrent = drgbcur.Length > 0 ? Convert.ToInt32(drgbcur) : 1;
                        wcurrent = dwcur.Length > 0 ? Convert.ToInt32(dwcur) : 1;
                        ccurrent = dccur.Length > 0 ? Convert.ToInt32(dccur) : 1;
                    }
                    catch
                    {
                        isExc = true;
                    }
                    finally
                    {
                        if (tg != null && !isExc) tg.initCommandLine += $"BP5758D_Current {rgbcurrent} {Math.Max(wcurrent, ccurrent)}\r\n";
                    }
                    currents = $"- RGB current is {(drgbcur.Length > 0 ? drgbcur : "Unknown")} mA" + Environment.NewLine;
                    currents += $"- Warm white current is {(dwcur.Length > 0 ? dwcur : "Unknown")} mA" + Environment.NewLine;
                    currents += $"- Cold white current is {(dccur.Length > 0 ? dccur : "Unknown")} mA" + Environment.NewLine;
                    tg?.setPinRole(iicsda, PinRole.BP5758D_DAT);
                    tg?.setPinRole(iicscl, PinRole.BP5758D_CLK);
                }
                else if (cjwcur.Length > 0)
                {
                    ledType = "BP1658CJ_";
                    var rgbcurrent = 1;
                    var cwcurrent = 1;
                    try
                    {
                        rgbcurrent = cjccur.Length > 0 ? Convert.ToInt32(cjccur) : 1;
                        cwcurrent = cjwcur.Length > 0 ? Convert.ToInt32(cjwcur) : 1;
                    }
                    catch
                    {
                        isExc = true;
                    }
                    finally
                    {
                        if (tg != null && !isExc) tg.initCommandLine += $"BP1658CJ_Current {rgbcurrent} {cwcurrent}\r\n";
                    }
                    currents = $"- RGB current is {(cjccur.Length > 0 ? cjccur : "Unknown")} mA" + Environment.NewLine;
                    currents += $"- White current is {(cjwcur.Length > 0 ? cjwcur : "Unknown")} mA" + Environment.NewLine;
                    tg?.setPinRole(iicsda, PinRole.BP1658CJ_DAT);
                    tg?.setPinRole(iicscl, PinRole.BP1658CJ_CLK);
                }
                else if (_2235ccur.Length > 0)
                {
                    ledType = "SM2235";
                    var rgbcurrent = 1;
                    var cwcurrent = 1;
                    try
                    {
                        rgbcurrent = _2235ccur.Length > 0 ? Convert.ToInt32(_2235ccur) : 1;
                        cwcurrent = _2235wcur.Length > 0 ? Convert.ToInt32(_2235wcur) : 1;
                    }
                    catch
                    {
                        isExc = true;
                    }
                    finally
                    {
                        if (tg != null && !isExc) tg.initCommandLine += $"SM2235_Current {rgbcurrent} {cwcurrent}\r\n";
                    }
                    currents = $"- RGB current is {(_2235ccur.Length > 0 ? _2235ccur : "Unknown")} mA" + Environment.NewLine;
                    currents += $"- White current is {(_2235wcur.Length > 0 ? _2235wcur : "Unknown")} mA" + Environment.NewLine;
                    tg?.setPinRole(iicsda, PinRole.SM2235DAT);
                    tg?.setPinRole(iicscl, PinRole.SM2235CLK);
                }
                else if (kp58wcur.Length > 0)
                {
                    ledType = "KP18058_";
                    var rgbcurrent = 1;
                    var cwcurrent = 1;
                    try
                    {
                        rgbcurrent = kp58wcur.Length > 0 ? Convert.ToInt32(kp58wcur) : 1;
                        cwcurrent = kp58ccur.Length > 0 ? Convert.ToInt32(kp58ccur) : 1;
                    }
                    catch
                    {
                        isExc = true;
                    }
                    finally
                    {
                        if (tg != null && !isExc) tg.initCommandLine += $"KP18058_Current {rgbcurrent} {cwcurrent}\r\n";
                    }
                    currents = $"- RGB current is {(kp58wcur.Length > 0 ? kp58wcur : "Unknown")} mA" + Environment.NewLine;
                    currents += $"- White current is {(kp58ccur.Length > 0 ? kp58ccur : "Unknown")} mA" + Environment.NewLine;
                    tg?.setPinRole(iicsda, PinRole.KP18058_DAT);
                    tg?.setPinRole(iicscl, PinRole.KP18058_CLK);
                }

                string dat_name = ledType + "DAT";
                string clk_name = ledType + "CLK";
                descSb.AppendLine($"- {dat_name} on P{iicsda}");
                descSb.AppendLine($"- {clk_name} on P{iicscl}");
                string map = $"{iicr} {iicg} {iicb} {iicc} {iicw}";
                isExc = false;
                try
                {
                    map = $"{Convert.ToInt32(iicr)} {Convert.ToInt32(iicg)} {Convert.ToInt32(iicb)} {Convert.ToInt32(iicc)} {Convert.ToInt32(iicw)}";
                }
                catch
                {
                    isExc = true;
                }
                finally
                {
                    if (tg != null && !isExc) tg.initCommandLine += $"LED_Map {map}\r\n";
                }
                descSb.AppendLine("- LED remap is " + map);
                descSb.AppendLine(currents);
                any = true;
            }

            if (!any)
            {
                return "Sorry, no meaningful pins data found. This device may be TuyaMCU or a custom one with no Tuya config data." + Environment.NewLine;
            }

            string result = "Device configuration, as extracted from Tuya: " + Environment.NewLine + descSb.ToString();

            // battery note
            bool bHasBattery = parms.ContainsKey("max_V") || parms.ContainsKey("min_V");
            if (bHasBattery)
            {
                result += "Device seems to use Battery Driver. See more details here: https://www.elektroda.com/rtvforum/topic3959103.html" + Environment.NewLine;
            }

            // module/baud info (preserve behavior)
            var baud = this.findKeyValue("baud");
            if (baud != null)
            {
                result += "Baud keyword found, this device may be TuyaMCU or BL0942. Baud value is " + baud + Environment.NewLine;
            }
            var kp = this.findKeyValue("module");
            kp ??= this.findKeyContaining("module");
            if (kp != null)
            {
                var type = TuyaModules.getTypeForModuleName(kp);
                result += "Device seems to be using " + kp + " module";
                if (type != nameof(BKType.Invalid))
                {
                    result += ", which is using " + type + ".";
                }
                else
                {
                    result += ".";
                }
            }
            else
            {
                result += "No module information found.";
            }

            result += Environment.NewLine;
            kp = findKeyValue("em_sys_env");
            if (kp != null)
            {
                result += Environment.NewLine;
                var type = TuyaModules.getTypeForPlatformName(kp);
                result += $"Device internal platform - {kp}";
                if (type != nameof(BKType.Invalid))
                {
                    result += ", equals " + type + ".";
                }
                else
                {
                    result += ".";
                }
            }

            result += Environment.NewLine;

            // print position info (same as before)
            void printposdevice(string device)
            {
                result += $"And the Tuya section starts at {getMagicPositionDecAndHex()}, which is a default {device} offset." + Environment.NewLine;
            }
            switch (magicPosition)
            {
                case 0:
                case 0x1000:
                    break;
                case USUAL_BK7231_MAGIC_POSITION:
                    result += $"And the Tuya section starts, as usual, at {getMagicPositionDecAndHex()}" + Environment.NewLine;
                    break;
                case USUAL_BK_NEW_XR806_MAGIC_POSITION:
                    printposdevice("T1/XR806 and some T34/BK7231N");
                    break;
                case USUAL_RTLC_ECR6600_MAGIC_POSITION:
                    printposdevice("RTL8720C and ECR6600");
                    break;
                case USUAL_RTLB_XR809_MAGIC_POSITION:
                    printposdevice("RTL8710B/XR809/BK7231Q");
                    break;
                case USUAL_T3_MAGIC_POSITION:
                    printposdevice("T3/BK7236");
                    break;
                case USUAL_T5_MAGIC_POSITION:
                    printposdevice("T5/BK7258");
                    break;
                case USUAL_RTLD_MAGIC_POSITION:
                    printposdevice("4MB RTL8720D");
                    break;
                case USUAL_WBRG1_MAGIC_POSITION:
                    printposdevice("8MB RTL8720D/WBRG1");
                    break;
                case USUAL_LN882H_MAGIC_POSITION:
                    printposdevice("LN882H");
                    break;
                case USUAL_TR6260_MAGIC_POSITION:
                    printposdevice("TR6260");
                    break;
                case USUAL_W800_MAGIC_POSITION:
                    printposdevice("W800");
                    break;
                case USUAL_LN8825_MAGIC_POSITION:
                    printposdevice("LN8825B");
                    break;
                case USUAL_RTLCM_MAGIC_POSITION:
                    printposdevice("RTL8720CM");
                    break;
                case USUAL_BK7252_MAGIC_POSITION:
                    printposdevice("BK7252");
                    break;
                default:
                    result += "And the Tuya section starts at an UNCOMMON POSITION " + getMagicPositionDecAndHex() + Environment.NewLine;
                    break;
            }

            return result;
        }

        public string getKeyValue(string key, string sdefault = "")
        {
            if (parms.TryGetValue(key, out var value))
                return value;
            return sdefault;
        }

        public string getKeysAsJSON()
        {
            string r = "{";
            foreach (var kv in parms)
            {
                r += Environment.NewLine + $"\t\"{kv.Key}\":\"{kv.Value}\",";
            }
            if (parms.Count > 0)
            {
                r = r.Substring(0, r.Length - 1); // remove last ','
                r += Environment.NewLine;
            }
            r += "}" + Environment.NewLine;
            return r;
        }

        public bool extractKeys()
        {
            var KVs = ParseVault();
            var KVs_Deduped = KVs
                .GroupBy(x => x.Key)
                .Select(g => g.OrderByDescending(x => x.IsCheckSumCorrect).First())
                .GroupBy(x => Convert.ToBase64String(x.Value))
                .Select(g => g.OrderByDescending(x => x.KeyId).First())
                .ToList();

            byte[] str = KVs_Deduped.FirstOrDefault(x => x.Key == "user_param_key" && x.IsCheckSumCorrect == true)?.Value ??
                KVs_Deduped.FirstOrDefault(x => x.Key == "baud_cfg" && x.IsCheckSumCorrect == true)?.Value;
            byte[] em_sys_env = KVs_Deduped.FirstOrDefault(x => x.Key == "em_sys_env" && x.IsCheckSumCorrect == true)?.Value;
            // old method. Works better when user_param_key is corrupted (bad checksum)
            if (str == null)
            {
                if (KVs.Any(x => x.Key == "user_param_key"))
                    FormMain.Singleton.addLog("Tuya user_param_key is corrupted, using old extraction method" + Environment.NewLine, System.Drawing.Color.Orange);
                int first_at = 0;
                int keys_at = MiscUtils.indexOf(descryptedRaw, Encoding.ASCII.GetBytes("user_param_key"));
                if (keys_at == -1)
                {
                    int jsonAt = MiscUtils.indexOf(descryptedRaw, Encoding.ASCII.GetBytes("Jsonver"));
                    if (jsonAt != -1)
                    {
                        keys_at = MiscUtils.findFirstRev(descryptedRaw, (byte)'{', jsonAt);
                    }
                    if (keys_at == -1)
                    {
                        keys_at = MiscUtils.indexOf(descryptedRaw, Encoding.ASCII.GetBytes("ap_s{"));

                        if (keys_at == -1)
                        {
                            keys_at = MiscUtils.indexOf(descryptedRaw, Encoding.ASCII.GetBytes("baud_cfg"));
                            if (keys_at == -1)
                            {
                                // ln882h hack
                                int jsonInOrig = MiscUtils.indexOf(original, Encoding.ASCII.GetBytes("crc:"));
                                if (jsonInOrig != -1 && original[jsonInOrig + 6] == ',' && original[jsonInOrig + 7] == '}')
                                {
                                    keys_at = jsonInOrig;
                                    descryptedRaw = original;
                                    while (descryptedRaw[keys_at] != '{' && keys_at <= descryptedRaw.Length)
                                        keys_at--;
                                    keys_at--;
                                }
                                // extract at least something
                                if (keys_at == -1)
                                {
                                    keys_at = MiscUtils.indexOf(descryptedRaw, Encoding.ASCII.GetBytes("gw_bi"));
                                    if (keys_at == -1)
                                    {
                                        FormMain.Singleton.addLog("Failed to extract Tuya keys - no json start found" + Environment.NewLine, System.Drawing.Color.Orange);
                                        return true;
                                    }
                                }
                            }
                            while (descryptedRaw[keys_at] != '{' && keys_at <= descryptedRaw.Length)
                                keys_at++;
                            keys_at++;
                            first_at = keys_at;
                        }
                        else
                        {
                            first_at = keys_at + 5;
                        }
                    }
                    else
                    {
                        first_at = keys_at + 1;
                    }
                }
                else
                {
                    while (descryptedRaw[keys_at] != '{' && keys_at <= descryptedRaw.Length)
                        keys_at++;
                    keys_at++;
                    first_at = keys_at;
                }
                int stopAT = MiscUtils.findMatching(descryptedRaw, (byte)'}', (byte)'{', first_at);
                if (stopAT == -1)
                {
                    stopAT = descryptedRaw.Length;
                }
                str = MiscUtils.subArray(descryptedRaw, first_at, stopAT - first_at);
            }
            // There is still some kind of Tuya paging here,
            // let's skip it in a quick and dirty way
            string asciiString = bytesToAsciiStr(str);
            string[] pairs = asciiString.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < pairs.Length; i++)
            {
                string[] kp = pairs[i].Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
                if (kp.Length < 2)
                {
                    FormMain.Singleton.addLog("Malformed key? " + Environment.NewLine, System.Drawing.Color.Orange);

                    continue;
                }
                string skey = (kp.Length > 2 && kp[1].Contains('[')) ? kp[1] : kp[0];
                string svalue = kp[kp.Length - 1];
                skey = skey.Trim(new char[] { '"' }).Replace("\"", "").Replace("[", "").Replace("{", "");
                svalue = svalue.Trim(new char[] { '"' }).Replace("\"", "").Replace("}", "");
                if (findKeyValue(skey) == null)
                {
                    parms.Add(skey, svalue);
                }
            }
            if (em_sys_env != null && !isFullOf(em_sys_env, 0x00))
            {
                parms.Add("em_sys_env", bytesToAsciiStr(em_sys_env));
            }
            FormMain.Singleton.addLog("Tuya keys extraction has found " + parms.Count + " keys" + Environment.NewLine, System.Drawing.Color.Black);

            return false;
        }

        string findKeyContaining(string key)
        {
            foreach (var kv in parms)
            {
                if (kv.Key.Contains(key, StringComparison.OrdinalIgnoreCase))
                    return kv.Value;
            }
            return null;
        }

        string findKeyValue(string key)
        {
            if (parms.TryGetValue(key, out var value))
                return value;
            return null;
        }

        bool checkCRC(uint expected, byte[] dat, int ofs, int len)
        {
            uint n = 0;
            for (int i = 0; i < len; i++)
            {
                n += dat[ofs + i];
            }
            n &= 0xFFFFFFFF;
            return n == expected;
        }

        string bytesToAsciiStr(byte[] data)
        {
            var asciiString = "";
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                if (b < 32) continue;
                if (b > 127) continue;
                char ch = (char)b;
                asciiString += ch;
            }
            return asciiString;
        }
    }
}
