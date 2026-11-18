using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace WorldApartSaveEditor
{
    // =========================================================================
    // 1. SimpleSave A1SV 加密与签名封装 (AES-256-CBC + HMAC-SHA256)
    // =========================================================================
    public static class SimpleSaveCrypto
    {
        private static readonly byte[] Magic = new byte[] { 0x41, 0x31, 0x53, 0x56 }; // "A1SV"
        private const byte FormatVersion = 1;
        private const byte KeyId = 1;
        private const int HeaderSize = 22; // 4 magic + 1 ver + 1 keyId + 16 IV
        private const int MacSize = 32;
        private const int MinEncryptedSize = 70;

        // 从 global-metadata.dat & GameAssembly.dll 提取的精确密钥
        private static readonly byte[] EncryptionKey = HexToBytes("eb972713304f73f1d06ff79304dc0048939a957250689a6937de9d1b60c77b9b");
        private static readonly byte[] AuthenticationKey = HexToBytes("67d92255f828454fb0176fc3262c47d56c77b070af57ae9f06b374ca883e10bd");

        private static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        public static bool IsEncrypted(byte[] data)
        {
            if (data == null || data.Length < 4) return false;
            return data[0] == Magic[0] && data[1] == Magic[1] && data[2] == Magic[2] && data[3] == Magic[3];
        }

        public static byte[] DecryptOrPassThrough(byte[] data, out bool wasEncrypted)
        {
            if (!IsEncrypted(data))
            {
                wasEncrypted = false;
                return data;
            }
            wasEncrypted = true;
            if (data.Length < MinEncryptedSize)
                throw new InvalidDataException("存档文件长度不足，可能已损坏。");
            if (data[4] != FormatVersion || data[5] != KeyId)
                throw new InvalidDataException(string.Format("不支持的加密存档版本 (ver={0}, keyId={1})。", data[4], data[5]));

            int cipherLen = data.Length - HeaderSize - MacSize;
            if (cipherLen <= 0 || (cipherLen % 16) != 0)
                throw new InvalidDataException("存档密文块长度无效。");

            using (var hmac = new HMACSHA256(AuthenticationKey))
            {
                byte[] computedMac = hmac.ComputeHash(data, 0, data.Length - MacSize);
                int macOffset = data.Length - MacSize;
                int diff = 0;
                for (int i = 0; i < MacSize; i++)
                    diff |= (computedMac[i] ^ data[macOffset + i]);
                if (diff != 0)
                    throw new InvalidDataException("存档完整性校验 (HMAC-SHA256) 失败！");
            }

            byte[] iv = new byte[16];
            Buffer.BlockCopy(data, 6, iv, 0, 16);

            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = EncryptionKey;
                aes.IV = iv;
                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, HeaderSize, cipherLen);
                }
            }
        }

        public static byte[] Encrypt(byte[] plaintext)
        {
            byte[] iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            byte[] ciphertext;
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = EncryptionKey;
                aes.IV = iv;
                using (var encryptor = aes.CreateEncryptor())
                {
                    ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
                }
            }

            byte[] output = new byte[HeaderSize + ciphertext.Length + MacSize];
            Buffer.BlockCopy(Magic, 0, output, 0, 4);
            output[4] = FormatVersion;
            output[5] = KeyId;
            Buffer.BlockCopy(iv, 0, output, 6, 16);
            Buffer.BlockCopy(ciphertext, 0, output, HeaderSize, ciphertext.Length);

            using (var hmac = new HMACSHA256(AuthenticationKey))
            {
                byte[] mac = hmac.ComputeHash(output, 0, HeaderSize + ciphertext.Length);
                Buffer.BlockCopy(mac, 0, output, HeaderSize + ciphertext.Length, MacSize);
            }

            return output;
        }
    }

    // =========================================================================
    // 2. 字节级无损保留的 MessagePack AST (Byte-Preserving MsgPack DOM)
    // =========================================================================
    public enum MsgPackKind
    {
        Nil,
        Bool,
        Int,
        UInt,
        Float,
        Double,
        String,
        Bin,
        Ext,
        Array,
        Map
    }

    public class MsgPackNode
    {
        public MsgPackKind Kind;
        public byte[] SourceBuffer;
        public int RawOffset;
        public int RawLength;
        public bool IsModified;
        public MsgPackNode Parent;

        public bool BoolVal;
        public long IntVal;
        public ulong UIntVal;
        public double FloatVal;
        public string StrVal;
        public byte[] BytesVal;
        public sbyte ExtType;
        public List<MsgPackNode> ArrayItems;
        public List<KeyValuePair<MsgPackNode, MsgPackNode>> MapEntries;

        public void MarkModified()
        {
            var cur = this;
            while (cur != null)
            {
                cur.IsModified = true;
                cur = cur.Parent;
            }
        }

        public static MsgPackNode CreateString(string s)
        {
            return new MsgPackNode { Kind = MsgPackKind.String, StrVal = s ?? "", IsModified = true };
        }

        public static MsgPackNode CreateInt(long v)
        {
            return new MsgPackNode { Kind = MsgPackKind.Int, IntVal = v, IsModified = true };
        }

        public static MsgPackNode CreateFloat(float f)
        {
            return new MsgPackNode { Kind = MsgPackKind.Float, FloatVal = f, IsModified = true };
        }

        public double AsDouble(double defaultVal = 0)
        {
            if (Kind == MsgPackKind.Float || Kind == MsgPackKind.Double) return FloatVal;
            if (Kind == MsgPackKind.Int) return IntVal;
            if (Kind == MsgPackKind.UInt) return UIntVal;
            return defaultVal;
        }

        // 用整数键查 Map（游戏里属性表的键是数字）
        public MsgPackNode GetMapValueByInt(long key)
        {
            if (Kind != MsgPackKind.Map || MapEntries == null) return null;
            for (int i = 0; i < MapEntries.Count; i++)
            {
                var k = MapEntries[i].Key;
                if ((k.Kind == MsgPackKind.Int || k.Kind == MsgPackKind.UInt) && k.AsInt64(long.MinValue) == key)
                    return MapEntries[i].Value;
            }
            return null;
        }

        public static MsgPackNode CreateBool(bool b)
        {
            return new MsgPackNode { Kind = MsgPackKind.Bool, BoolVal = b, IsModified = true };
        }

        public static MsgPackNode CreateArray(List<MsgPackNode> items = null)
        {
            var node = new MsgPackNode
            {
                Kind = MsgPackKind.Array,
                ArrayItems = items ?? new List<MsgPackNode>(),
                IsModified = true
            };
            foreach (var item in node.ArrayItems)
                item.Parent = node;
            return node;
        }

        public static MsgPackNode CreateMap()
        {
            return new MsgPackNode
            {
                Kind = MsgPackKind.Map,
                MapEntries = new List<KeyValuePair<MsgPackNode, MsgPackNode>>(),
                IsModified = true
            };
        }

        public string AsString()
        {
            if (Kind == MsgPackKind.String) return StrVal;
            if (Kind == MsgPackKind.Int) return IntVal.ToString();
            if (Kind == MsgPackKind.UInt) return UIntVal.ToString();
            return null;
        }

        public long AsInt64(long defaultVal = 0)
        {
            if (Kind == MsgPackKind.Int) return IntVal;
            if (Kind == MsgPackKind.UInt) return (long)UIntVal;
            return defaultVal;
        }

        public int AsInt32(int defaultVal = 0)
        {
            return (int)AsInt64(defaultVal);
        }

        public bool AsBool(bool defaultVal = false)
        {
            if (Kind == MsgPackKind.Bool) return BoolVal;
            return defaultVal;
        }

        public MsgPackNode GetMapValue(string key)
        {
            if (Kind != MsgPackKind.Map || MapEntries == null) return null;
            for (int i = 0; i < MapEntries.Count; i++)
            {
                var k = MapEntries[i].Key;
                if (k.Kind == MsgPackKind.String && k.StrVal == key)
                    return MapEntries[i].Value;
            }
            return null;
        }

        public void SetMapValue(string key, MsgPackNode val)
        {
            if (Kind != MsgPackKind.Map)
                throw new InvalidOperationException("Not a Map node.");
            val.Parent = this;
            for (int i = 0; i < MapEntries.Count; i++)
            {
                var k = MapEntries[i].Key;
                if (k.Kind == MsgPackKind.String && k.StrVal == key)
                {
                    MapEntries[i] = new KeyValuePair<MsgPackNode, MsgPackNode>(k, val);
                    MarkModified();
                    return;
                }
            }
            var keyNode = CreateString(key);
            keyNode.Parent = this;
            MapEntries.Add(new KeyValuePair<MsgPackNode, MsgPackNode>(keyNode, val));
            MarkModified();
        }

        public void SetIntValue(long v)
        {
            Kind = MsgPackKind.Int;
            IntVal = v;
            MarkModified();
        }

        public void SetBoolValue(bool b)
        {
            Kind = MsgPackKind.Bool;
            BoolVal = b;
            MarkModified();
        }

        public static MsgPackNode Parse(byte[] buffer)
        {
            int pos = 0;
            return ParseInternal(buffer, ref pos, null);
        }

        private static MsgPackNode ParseInternal(byte[] buf, ref int pos, MsgPackNode parent)
        {
            int start = pos;
            byte b = buf[pos++];
            var node = new MsgPackNode { SourceBuffer = buf, RawOffset = start, Parent = parent };

            if (b <= 0x7f)
            {
                node.Kind = MsgPackKind.Int;
                node.IntVal = b;
            }
            else if (b >= 0xe0)
            {
                node.Kind = MsgPackKind.Int;
                node.IntVal = unchecked((sbyte)b);
            }
            else if (b >= 0x80 && b <= 0x8f)
            {
                ReadMapBody(buf, ref pos, node, b & 0x0f);
            }
            else if (b >= 0x90 && b <= 0x9f)
            {
                ReadArrayBody(buf, ref pos, node, b & 0x0f);
            }
            else if (b >= 0xa0 && b <= 0xbf)
            {
                ReadStrBody(buf, ref pos, node, b & 0x1f);
            }
            else
            {
                switch (b)
                {
                    case 0xc0:
                        node.Kind = MsgPackKind.Nil;
                        break;
                    case 0xc2:
                        node.Kind = MsgPackKind.Bool;
                        node.BoolVal = false;
                        break;
                    case 0xc3:
                        node.Kind = MsgPackKind.Bool;
                        node.BoolVal = true;
                        break;
                    case 0xc4:
                        ReadBinBody(buf, ref pos, node, buf[pos++]);
                        break;
                    case 0xc5:
                        ReadBinBody(buf, ref pos, node, ReadUInt16BE(buf, ref pos));
                        break;
                    case 0xc6:
                        ReadBinBody(buf, ref pos, node, (int)ReadUInt32BE(buf, ref pos));
                        break;
                    case 0xc7:
                        {
                            int len = buf[pos++];
                            node.ExtType = unchecked((sbyte)buf[pos++]);
                            ReadExtBody(buf, ref pos, node, len);
                            break;
                        }
                    case 0xc8:
                        {
                            int len = ReadUInt16BE(buf, ref pos);
                            node.ExtType = unchecked((sbyte)buf[pos++]);
                            ReadExtBody(buf, ref pos, node, len);
                            break;
                        }
                    case 0xc9:
                        {
                            int len = (int)ReadUInt32BE(buf, ref pos);
                            node.ExtType = unchecked((sbyte)buf[pos++]);
                            ReadExtBody(buf, ref pos, node, len);
                            break;
                        }
                    case 0xca:
                        {
                            node.Kind = MsgPackKind.Float;
                            byte[] tmp = new byte[4];
                            tmp[3] = buf[pos++]; tmp[2] = buf[pos++]; tmp[1] = buf[pos++]; tmp[0] = buf[pos++];
                            node.FloatVal = BitConverter.ToSingle(tmp, 0);
                            break;
                        }
                    case 0xcb:
                        {
                            node.Kind = MsgPackKind.Double;
                            byte[] tmp = new byte[8];
                            for (int i = 7; i >= 0; i--) tmp[i] = buf[pos++];
                            node.FloatVal = BitConverter.ToDouble(tmp, 0);
                            break;
                        }
                    case 0xcc:
                        node.Kind = MsgPackKind.Int;
                        node.IntVal = buf[pos++];
                        break;
                    case 0xcd:
                        node.Kind = MsgPackKind.Int;
                        node.IntVal = ReadUInt16BE(buf, ref pos);
                        break;
                    case 0xce:
                        node.Kind = MsgPackKind.Int;
                        node.IntVal = ReadUInt32BE(buf, ref pos);
                        break;
                    case 0xcf:
                        node.Kind = MsgPackKind.UInt;
                        node.UIntVal = ReadUInt64BE(buf, ref pos);
                        node.IntVal = unchecked((long)node.UIntVal);
                        break;
                    case 0xd0:
                        node.Kind = MsgPackKind.Int;
                        node.IntVal = unchecked((sbyte)buf[pos++]);
                        break;
                    case 0xd1:
                        node.Kind = MsgPackKind.Int;
                        node.IntVal = unchecked((short)ReadUInt16BE(buf, ref pos));
                        break;
                    case 0xd2:
                        node.Kind = MsgPackKind.Int;
                        node.IntVal = unchecked((int)ReadUInt32BE(buf, ref pos));
                        break;
                    case 0xd3:
                        node.Kind = MsgPackKind.Int;
                        node.IntVal = unchecked((long)ReadUInt64BE(buf, ref pos));
                        break;
                    case 0xd4:
                        node.ExtType = unchecked((sbyte)buf[pos++]);
                        ReadExtBody(buf, ref pos, node, 1);
                        break;
                    case 0xd5:
                        node.ExtType = unchecked((sbyte)buf[pos++]);
                        ReadExtBody(buf, ref pos, node, 2);
                        break;
                    case 0xd6:
                        node.ExtType = unchecked((sbyte)buf[pos++]);
                        ReadExtBody(buf, ref pos, node, 4);
                        break;
                    case 0xd7:
                        node.ExtType = unchecked((sbyte)buf[pos++]);
                        ReadExtBody(buf, ref pos, node, 8);
                        break;
                    case 0xd8:
                        node.ExtType = unchecked((sbyte)buf[pos++]);
                        ReadExtBody(buf, ref pos, node, 16);
                        break;
                    case 0xd9:
                        ReadStrBody(buf, ref pos, node, buf[pos++]);
                        break;
                    case 0xda:
                        ReadStrBody(buf, ref pos, node, ReadUInt16BE(buf, ref pos));
                        break;
                    case 0xdb:
                        ReadStrBody(buf, ref pos, node, (int)ReadUInt32BE(buf, ref pos));
                        break;
                    case 0xdc:
                        ReadArrayBody(buf, ref pos, node, ReadUInt16BE(buf, ref pos));
                        break;
                    case 0xdd:
                        ReadArrayBody(buf, ref pos, node, (int)ReadUInt32BE(buf, ref pos));
                        break;
                    case 0xde:
                        ReadMapBody(buf, ref pos, node, ReadUInt16BE(buf, ref pos));
                        break;
                    case 0xdf:
                        ReadMapBody(buf, ref pos, node, (int)ReadUInt32BE(buf, ref pos));
                        break;
                    default:
                        throw new InvalidDataException(string.Format("未知的 MessagePack 标记 0x{0:X2} (位置 {1})", b, start));
                }
            }

            node.RawLength = pos - start;
            return node;
        }

        private static ushort ReadUInt16BE(byte[] buf, ref int pos)
        {
            ushort v = (ushort)((buf[pos] << 8) | buf[pos + 1]);
            pos += 2;
            return v;
        }

        private static uint ReadUInt32BE(byte[] buf, ref int pos)
        {
            uint v = ((uint)buf[pos] << 24) | ((uint)buf[pos + 1] << 16) | ((uint)buf[pos + 2] << 8) | buf[pos + 3];
            pos += 4;
            return v;
        }

        private static ulong ReadUInt64BE(byte[] buf, ref int pos)
        {
            ulong hi = ReadUInt32BE(buf, ref pos);
            ulong lo = ReadUInt32BE(buf, ref pos);
            return (hi << 32) | lo;
        }

        private static void ReadStrBody(byte[] buf, ref int pos, MsgPackNode node, int len)
        {
            node.Kind = MsgPackKind.String;
            node.StrVal = len > 0 ? Encoding.UTF8.GetString(buf, pos, len) : "";
            pos += len;
        }

        private static void ReadBinBody(byte[] buf, ref int pos, MsgPackNode node, int len)
        {
            node.Kind = MsgPackKind.Bin;
            pos += len;
        }

        private static void ReadExtBody(byte[] buf, ref int pos, MsgPackNode node, int len)
        {
            node.Kind = MsgPackKind.Ext;
            pos += len;
        }

        private static void ReadArrayBody(byte[] buf, ref int pos, MsgPackNode node, int count)
        {
            node.Kind = MsgPackKind.Array;
            node.ArrayItems = new List<MsgPackNode>(count);
            for (int i = 0; i < count; i++)
            {
                node.ArrayItems.Add(ParseInternal(buf, ref pos, node));
            }
        }

        private static void ReadMapBody(byte[] buf, ref int pos, MsgPackNode node, int count)
        {
            node.Kind = MsgPackKind.Map;
            node.MapEntries = new List<KeyValuePair<MsgPackNode, MsgPackNode>>(count);
            for (int i = 0; i < count; i++)
            {
                var k = ParseInternal(buf, ref pos, node);
                var v = ParseInternal(buf, ref pos, node);
                node.MapEntries.Add(new KeyValuePair<MsgPackNode, MsgPackNode>(k, v));
            }
        }

        public byte[] ToBytes()
        {
            using (var ms = new MemoryStream(RawLength > 0 ? RawLength + 1024 : 4096))
            {
                WriteTo(ms);
                return ms.ToArray();
            }
        }

        public void WriteTo(Stream s)
        {
            if (!IsModified && SourceBuffer != null && RawLength > 0)
            {
                s.Write(SourceBuffer, RawOffset, RawLength);
                return;
            }

            switch (Kind)
            {
                case MsgPackKind.Nil:
                    s.WriteByte(0xc0);
                    break;
                case MsgPackKind.Bool:
                    s.WriteByte(BoolVal ? (byte)0xc3 : (byte)0xc2);
                    break;
                case MsgPackKind.Int:
                    WriteInt64(s, IntVal);
                    break;
                case MsgPackKind.UInt:
                    WriteUInt64(s, UIntVal);
                    break;
                case MsgPackKind.String:
                    WriteString(s, StrVal ?? "");
                    break;
                case MsgPackKind.Float:
                    {
                        byte[] fb = BitConverter.GetBytes((float)FloatVal);
                        s.WriteByte(0xca);
                        s.WriteByte(fb[3]); s.WriteByte(fb[2]); s.WriteByte(fb[1]); s.WriteByte(fb[0]);
                        break;
                    }
                case MsgPackKind.Double:
                    {
                        byte[] db = BitConverter.GetBytes(FloatVal);
                        s.WriteByte(0xcb);
                        for (int i = 7; i >= 0; i--) s.WriteByte(db[i]);
                        break;
                    }
                case MsgPackKind.Array:
                    {
                        int n = ArrayItems != null ? ArrayItems.Count : 0;
                        if (n <= 15)
                        {
                            s.WriteByte((byte)(0x90 | n));
                        }
                        else if (n <= 65535)
                        {
                            s.WriteByte(0xdc);
                            WriteUInt16BE(s, (ushort)n);
                        }
                        else
                        {
                            s.WriteByte(0xdd);
                            WriteUInt32BE(s, (uint)n);
                        }
                        for (int i = 0; i < n; i++)
                            ArrayItems[i].WriteTo(s);
                        break;
                    }
                case MsgPackKind.Map:
                    {
                        int n = MapEntries != null ? MapEntries.Count : 0;
                        if (n <= 15)
                        {
                            s.WriteByte((byte)(0x80 | n));
                        }
                        else if (n <= 65535)
                        {
                            s.WriteByte(0xde);
                            WriteUInt16BE(s, (ushort)n);
                        }
                        else
                        {
                            s.WriteByte(0xdf);
                            WriteUInt32BE(s, (uint)n);
                        }
                        for (int i = 0; i < n; i++)
                        {
                            MapEntries[i].Key.WriteTo(s);
                            MapEntries[i].Value.WriteTo(s);
                        }
                        break;
                    }
                default:
                    if (SourceBuffer != null && RawLength > 0)
                        s.Write(SourceBuffer, RawOffset, RawLength);
                    break;
            }
        }

        private static void WriteUInt16BE(Stream s, ushort v)
        {
            s.WriteByte((byte)(v >> 8));
            s.WriteByte((byte)(v & 0xff));
        }

        private static void WriteUInt32BE(Stream s, uint v)
        {
            s.WriteByte((byte)(v >> 24));
            s.WriteByte((byte)((v >> 16) & 0xff));
            s.WriteByte((byte)((v >> 8) & 0xff));
            s.WriteByte((byte)(v & 0xff));
        }

        private static void WriteInt64(Stream s, long v)
        {
            if (v >= 0)
            {
                WriteUInt64(s, (ulong)v);
            }
            else if (v >= -32)
            {
                s.WriteByte(unchecked((byte)(sbyte)v));
            }
            else if (v >= sbyte.MinValue)
            {
                s.WriteByte(0xd0);
                s.WriteByte(unchecked((byte)(sbyte)v));
            }
            else if (v >= short.MinValue)
            {
                s.WriteByte(0xd1);
                WriteUInt16BE(s, unchecked((ushort)(short)v));
            }
            else if (v >= int.MinValue)
            {
                s.WriteByte(0xd2);
                WriteUInt32BE(s, unchecked((uint)(int)v));
            }
            else
            {
                s.WriteByte(0xd3);
                ulong uv = unchecked((ulong)v);
                WriteUInt32BE(s, (uint)(uv >> 32));
                WriteUInt32BE(s, (uint)(uv & 0xffffffffUL));
            }
        }

        private static void WriteUInt64(Stream s, ulong v)
        {
            if (v <= 0x7f)
            {
                s.WriteByte((byte)v);
            }
            else if (v <= byte.MaxValue)
            {
                s.WriteByte(0xcc);
                s.WriteByte((byte)v);
            }
            else if (v <= ushort.MaxValue)
            {
                s.WriteByte(0xcd);
                WriteUInt16BE(s, (ushort)v);
            }
            else if (v <= uint.MaxValue)
            {
                s.WriteByte(0xce);
                WriteUInt32BE(s, (uint)v);
            }
            else
            {
                s.WriteByte(0xcf);
                WriteUInt32BE(s, (uint)(v >> 32));
                WriteUInt32BE(s, (uint)(v & 0xffffffffUL));
            }
        }

        private static void WriteString(Stream s, string str)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(str);
            int len = bytes.Length;
            if (len <= 31)
            {
                s.WriteByte((byte)(0xa0 | len));
            }
            else if (len <= 255)
            {
                s.WriteByte(0xd9);
                s.WriteByte((byte)len);
            }
            else if (len <= 65535)
            {
                s.WriteByte(0xda);
                WriteUInt16BE(s, (ushort)len);
            }
            else
            {
                s.WriteByte(0xdb);
                WriteUInt32BE(s, (uint)len);
            }
            if (len > 0)
                s.Write(bytes, 0, len);
        }
    }

    // =========================================================================
    // 3. 静态配置数据模型 (从内嵌资源加载)
    // =========================================================================
    public class TalentInfo
    {
        public int Id;
        public string Name;
        public int Quality;
        public int Category;
        public int RealmId;
        public bool PreviewOnly;
        public string Desc;

        public string QualityText
        {
            get
            {
                switch (Quality)
                {
                    case 5: return "仙品·红";
                    case 4: return "极品·金";
                    case 3: return "上品·紫";
                    case 2: return "良品·蓝";
                    default: return "凡品·绿";
                }
            }
        }

        public string CategoryText
        {
            get
            {
                switch (Category)
                {
                    case 1: return "战斗";
                    case 2: return "修炼";
                    case 3: return "游历/采集";
                    case 4: return "丹器/经商";
                    case 5: return "社交/同道";
                    case 6: return "性格/固有";
                    default: return "其他";
                }
            }
        }

        public string DisplayText
        {
            get
            {
                string p = PreviewOnly ? " [占位未实装]" : "";
                return string.Format("[{0} | {1}] {2} ({3}){4} — {5}", QualityText, CategoryText, Name, Id, p, Desc);
            }
        }

        public override string ToString()
        {
            return DisplayText;
        }
    }

    public class NpcSlotConfigInfo
    {
        public int SlotId;
        public int InitType;
        public int FixedTalentId;
        public int PoolId;
        public int RequiredRealmId;
    }

    public class NpcConfigInfo
    {
        public int Id;
        public string Name;
        public string Title;
        public bool CanBeDaoCompanion;
        public List<NpcSlotConfigInfo> Slots = new List<NpcSlotConfigInfo>();
        public string SheetSlotsSummary;
        public string SheetUnlockCond;
    }

    public class DaoPathNodeInfo
    {
        public int Id;
        public string PathName;
        public string Name;
        public int Cost;
        public string Desc;
    }

    public class ItemInfo
    {
        public int Id;
        public string Name;
        public int ItemType;
        public string TypeName;
        public string BagName;
        public int Quality;
        public long MaxPerGrid;
        public int Addable; // 0 = 不可添加, 1 = 已验证, 2 = 未验证, 3 = 任务物品（需确认）
        public string Desc;
        public int Format;  // 存档格式：0 普通 / 2 法宝(未炼制) / 3 丹药 / 4 璞石(未鉴定) / 5 功法心法
        public string Params;

        public string StatusText
        {
            get
            {
                switch (Addable)
                {
                    case 1: return "可添加";
                    case 2: return "⚠未验证";
                    case 3: return "任务物品";
                    default: return "不可添加";
                }
            }
        }

        public string QualityText
        {
            get
            {
                switch (Quality)
                {
                    case 5: return "红";
                    case 4: return "金";
                    case 3: return "紫";
                    case 2: return "蓝";
                    case 1: return "绿";
                    default: return "—";
                }
            }
        }
    }

    public class AffixInfo
    {
        public int Id;
        public int PoolId;
        public string Realm;
        public int Quality;      // 0白 1绿 2蓝 3紫 4橙
        public int AttrId;
        public string DescTemplate;
        public double Min;
        public double Max;
        public bool Disabled;    // 游戏标注"待程序支持后启用"

        public static readonly string[] QualityNames = { "白", "绿", "蓝", "紫", "橙" };

        public string QualityText { get { return Quality >= 0 && Quality < QualityNames.Length ? QualityNames[Quality] : "?"; } }

        public override string ToString()
        {
            return string.Format("[{0}·{1}] {2}  ({3}~{4}){5}", Realm, QualityText, DescTemplate.Replace("{0}", ""), Min, Max, Disabled ? "  ⚠未实装" : "");
        }
    }

    public static class GameDatabase
    {
        public static Dictionary<int, AffixInfo> Affixes = new Dictionary<int, AffixInfo>();
        public static List<AffixInfo> AffixList = new List<AffixInfo>();
        public static Dictionary<int, string> AttrNames = new Dictionary<int, string>();
        public static Dictionary<int, ItemInfo> Items = new Dictionary<int, ItemInfo>();
        public static List<ItemInfo> ItemList = new List<ItemInfo>();
        public static Dictionary<int, TalentInfo> Talents = new Dictionary<int, TalentInfo>();
        public static List<TalentInfo> TalentList = new List<TalentInfo>();
        public static Dictionary<int, NpcConfigInfo> Npcs = new Dictionary<int, NpcConfigInfo>();
        public static List<NpcConfigInfo> NpcList = new List<NpcConfigInfo>();
        public static Dictionary<int, DaoPathNodeInfo> DaoNodes = new Dictionary<int, DaoPathNodeInfo>();

        public static void LoadEmbedded()
        {
            var asm = Assembly.GetExecutingAssembly();
            LoadTalents(ReadResourceLines(asm, "talent_db.tsv"));
            LoadNpcs(ReadResourceLines(asm, "npc_db.tsv"));
            LoadDaoNodes(ReadResourceLines(asm, "daopath_db.tsv"));
            LoadItems(ReadResourceLines(asm, "item_db.tsv"));
            LoadAffixes(ReadResourceLines(asm, "affix_db.tsv"));
            MiscDatabase.Load(ReadResourceLines(asm, "misc_db.tsv"));
            PillDatabase.Load(ReadResourceLines(asm, "pill_db.tsv"));
            AttrNames.Clear();
            foreach (var line in ReadResourceLines(asm, "attr_db.tsv"))
            {
                var p = line.Split('\t');
                if (p.Length >= 2) AttrNames[int.Parse(p[0])] = p[1];
            }
        }

        public static string AttrName(int id)
        {
            string n;
            return AttrNames.TryGetValue(id, out n) ? n : ("属性" + id);
        }

        private static void LoadAffixes(string[] lines)
        {
            Affixes.Clear();
            AffixList.Clear();
            var ci = System.Globalization.CultureInfo.InvariantCulture;
            foreach (var line in lines)
            {
                var p = line.Split('\t');
                if (p.Length < 9) continue;
                var a = new AffixInfo
                {
                    Id = int.Parse(p[0]),
                    PoolId = int.Parse(p[1]),
                    Realm = p[2],
                    Quality = int.Parse(p[3]),
                    AttrId = int.Parse(p[4]),
                    DescTemplate = p[5],
                    Min = double.Parse(p[6], ci),
                    Max = double.Parse(p[7], ci),
                    Disabled = p[8] == "1"
                };
                Affixes[a.Id] = a;
                AffixList.Add(a);
            }
            AffixList = AffixList.OrderBy(x => x.PoolId).ThenBy(x => x.AttrId).ThenBy(x => x.Quality).ToList();
        }

        private static void LoadItems(string[] lines)
        {
            Items.Clear();
            ItemList.Clear();
            var tagRx = new System.Text.RegularExpressions.Regex("<[^>]+>");
            foreach (var line in lines)
            {
                var p = line.Split('\t');
                if (p.Length < 9) continue;
                var it = new ItemInfo
                {
                    Id = int.Parse(p[0]),
                    Name = p[1],
                    ItemType = int.Parse(p[2]),
                    TypeName = p[3],
                    BagName = p[4],
                    Quality = int.Parse(p[5]),
                    MaxPerGrid = Math.Max(1, long.Parse(p[6])),
                    Addable = int.Parse(p[7]),
                    Desc = tagRx.Replace(p[8], ""),
                    Format = p.Length > 9 && p[9].Length > 0 ? int.Parse(p[9]) : 0,
                    Params = p.Length > 10 ? p[10] : ""
                };
                Items[it.Id] = it;
                ItemList.Add(it);
            }
        }

        private static string[] ReadResourceLines(Assembly asm, string resName)
        {
            using (var s = asm.GetManifestResourceStream(resName))
            {
                if (s == null) return new string[0];
                using (var sr = new StreamReader(s, Encoding.UTF8))
                {
                    return sr.ReadToEnd().Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
        }

        private static void LoadTalents(string[] lines)
        {
            Talents.Clear();
            TalentList.Clear();
            foreach (var line in lines)
            {
                var p = line.Split('\t');
                if (p.Length < 7) continue;
                var t = new TalentInfo
                {
                    Id = int.Parse(p[0]),
                    Name = p[1],
                    Quality = int.Parse(p[2]),
                    Category = int.Parse(p[3]),
                    RealmId = int.Parse(p[4]),
                    PreviewOnly = p[5] == "1",
                    Desc = p[6]
                };
                Talents[t.Id] = t;
                TalentList.Add(t);
            }
        }

        private static void LoadNpcs(string[] lines)
        {
            Npcs.Clear();
            NpcList.Clear();
            foreach (var line in lines)
            {
                var p = line.Split('\t');
                if (p.Length < 5) continue;
                var npc = new NpcConfigInfo
                {
                    Id = int.Parse(p[0]),
                    Name = p[1],
                    Title = p[2],
                    CanBeDaoCompanion = p[3] == "1",
                    SheetSlotsSummary = p.Length > 5 ? p[5] : "",
                    SheetUnlockCond = p.Length > 6 ? p[6] : ""
                };
                if (!string.IsNullOrEmpty(p[4]))
                {
                    foreach (var sp in p[4].Split(','))
                    {
                        var kv = sp.Split(':');
                        if (kv.Length >= 5)
                        {
                            npc.Slots.Add(new NpcSlotConfigInfo
                            {
                                SlotId = int.Parse(kv[0]),
                                InitType = int.Parse(kv[1]),
                                FixedTalentId = int.Parse(kv[2]),
                                PoolId = int.Parse(kv[3]),
                                RequiredRealmId = int.Parse(kv[4])
                            });
                        }
                    }
                }
                Npcs[npc.Id] = npc;
                NpcList.Add(npc);
            }
        }

        private static void LoadDaoNodes(string[] lines)
        {
            DaoNodes.Clear();
            foreach (var line in lines)
            {
                var p = line.Split('\t');
                if (p.Length < 5) continue;
                var nd = new DaoPathNodeInfo
                {
                    Id = int.Parse(p[0]),
                    PathName = p[1],
                    Name = p[2],
                    Cost = int.Parse(p[3]),
                    Desc = p[4]
                };
                DaoNodes[nd.Id] = nd;
            }
        }
    }

    // =========================================================================
    // 4. 持续锁定的修改项模型 (支持游戏运行中自动合并并覆盖最新运行存档)
    // =========================================================================
    // =========================================================================
    // 额外配置数据（misc_db.tsv）
    // =========================================================================
    public class LayerInfo { public int Id; public string Name; public long NpcExp; public int Realm; public override string ToString() { return Name; } }
    public class RealmInfo { public int Id; public string Name; public int AllyCapacity; }
    public class PillLevelInfo { public int Level; public long Exp; public string Title; public int RequiredLayer; public override string ToString() { return string.Format("{0} 级 · {1}", Level, Title); } }
    public class FurnaceInfo { public int Id; public string Name; public int ItemId; public override string ToString() { return Id + " · " + Name; } }
    public class ProtoTier { public int Tier; public long ScoreMin; public List<KeyValuePair<int, double>> Attrs = new List<KeyValuePair<int, double>>(); }
    public class PassiveInfo { public int Id; public string Name; public int Tier; public List<int> InitSkills = new List<int>(); public int SlotCount; public int BookItemId; }
    public class SkillInfo { public int Id; public string Name; public int AbilityKind; public int Tier; public int BookItemId; }
    public class ForgeLevelInfo { public int Level; public string Title; public long Exp; public int PointReward; public List<int> Unlocks = new List<int>(); public override string ToString() { return string.Format("{0} 级 · {1}", Level, Title); } }
    public class ForgeTalentInfo { public int Id; public string Name; public string Desc; public int ReqLevel; public int Cost; public override string ToString() { return string.Format("{0}（{1}级，{2}点）— {3}", Name, ReqLevel, Cost, Desc); } }

    public static class MiscDatabase
    {
        public static List<LayerInfo> Layers = new List<LayerInfo>();
        public static Dictionary<int, RealmInfo> Realms = new Dictionary<int, RealmInfo>();
        public static Dictionary<int, string> Towns = new Dictionary<int, string>();
        public static Dictionary<int, string> Sects = new Dictionary<int, string>();
        public static List<PillLevelInfo> PillLevels = new List<PillLevelInfo>();
        public static List<FurnaceInfo> Furnaces = new List<FurnaceInfo>();
        public static Dictionary<int, List<ProtoTier>> Protos = new Dictionary<int, List<ProtoTier>>();
        public static Dictionary<int, PassiveInfo> Passives = new Dictionary<int, PassiveInfo>();
        public static Dictionary<int, SkillInfo> Skills = new Dictionary<int, SkillInfo>();
        public static List<ForgeLevelInfo> ForgeLevels = new List<ForgeLevelInfo>();
        public static List<ForgeTalentInfo> ForgeTalents = new List<ForgeTalentInfo>();

        public static void Load(string[] lines)
        {
            var ci = System.Globalization.CultureInfo.InvariantCulture;
            foreach (var line in lines)
            {
                var p = line.Split('\t');
                if (p.Length < 3) continue;
                int id;
                if (!int.TryParse(p[1], out id)) continue;
                switch (p[0])
                {
                    case "layer": Layers.Add(new LayerInfo { Id = id, Name = p[2], NpcExp = p.Length > 3 ? long.Parse(p[3]) : 0, Realm = p.Length > 4 ? int.Parse(p[4]) : 0 }); break;
                    case "realm": Realms[id] = new RealmInfo { Id = id, Name = p[2], AllyCapacity = p.Length > 3 ? int.Parse(p[3]) : 0 }; break;
                    case "town": Towns[id] = p[2]; break;
                    case "sect": Sects[id] = p[2]; break;
                    case "plevel": PillLevels.Add(new PillLevelInfo { Level = id, Exp = long.Parse(p[2]), Title = p[3], RequiredLayer = int.Parse(p[4]) }); break;
                    case "furnace": Furnaces.Add(new FurnaceInfo { Id = id, Name = p[2], ItemId = int.Parse(p[3]) }); break;
                    case "proto":
                        {
                            var tiers = new List<ProtoTier>();
                            foreach (var t in p[2].Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                var f = t.Split(':');
                                var pt = new ProtoTier { Tier = int.Parse(f[0]), ScoreMin = long.Parse(f[1]) };
                                if (f.Length > 2)
                                    foreach (var a in f[2].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                                    {
                                        var kv = a.Split('=');
                                        pt.Attrs.Add(new KeyValuePair<int, double>(int.Parse(kv[0]), double.Parse(kv[1], ci)));
                                    }
                                tiers.Add(pt);
                            }
                            Protos[id] = tiers;
                            break;
                        }
                    case "passive":
                        {
                            var pi = new PassiveInfo { Id = id, Name = p[2], Tier = int.Parse(p[3]), SlotCount = int.Parse(p[5]), BookItemId = int.Parse(p[6]) };
                            foreach (var s in p[4].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)) pi.InitSkills.Add(int.Parse(s));
                            Passives[id] = pi;
                            break;
                        }
                    case "skill":
                        Skills[id] = new SkillInfo { Id = id, Name = p[2], AbilityKind = int.Parse(p[3]), Tier = int.Parse(p[4]), BookItemId = int.Parse(p[5]) };
                        break;
                    case "alevel":
                        {
                            var fl = new ForgeLevelInfo { Level = id, Title = p[2], Exp = long.Parse(p[3]), PointReward = int.Parse(p[4]) };
                            if (p.Length > 5) foreach (var s in p[5].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)) fl.Unlocks.Add(int.Parse(s));
                            ForgeLevels.Add(fl);
                            break;
                        }
                    case "atalent":
                        ForgeTalents.Add(new ForgeTalentInfo { Id = id, Name = p[2], Desc = p[3], ReqLevel = int.Parse(p[4]), Cost = int.Parse(p[5]) });
                        break;
                }
            }
        }

        public static string LayerName(long id)
        {
            var l = Layers.FirstOrDefault(x => x.Id == id);
            return l != null ? l.Name : ("第" + id + "层");
        }
    }

    // =========================================================================
    // 炼丹数据（pill_db.tsv）
    // =========================================================================
    public class PillRecipeInfo { public int Id; public string Name; public int Tier; public int Element; public string Category; public bool Enabled; public int MaxUse; public int ItemId; public string Hint; public string Source; }
    public class PillEffectInfo
    {
        public int Id; public string Name; public int Tier; public int Element; public string Desc;
        public override string ToString() { return string.Format("{0}（{1}阶·{2}）— {3}", Name, Tier, PillDatabase.ElementName(Element), Desc); }
    }
    public class PillTalentLevel { public int Rank; public string Value; public int Cost; public int ReqLevel; }
    public class PillTalentInfo { public int Id; public string Name; public string Phase; public string Desc; public List<PillTalentLevel> Levels = new List<PillTalentLevel>(); }

    public static class PillDatabase
    {
        public static List<PillRecipeInfo> Recipes = new List<PillRecipeInfo>();
        public static List<PillEffectInfo> Effects = new List<PillEffectInfo>();
        public static List<PillTalentInfo> Talents = new List<PillTalentInfo>();
        private static readonly string[] Elements = { "无", "金", "木", "水", "火", "土" };
        public static string ElementName(int e) { return e >= 0 && e < Elements.Length ? Elements[e] : "?"; }

        public static void Load(string[] lines)
        {
            foreach (var line in lines)
            {
                var p = line.Split('\t');
                if (p.Length < 3) continue;
                int id;
                if (!int.TryParse(p[1], out id)) continue;
                switch (p[0])
                {
                    case "recipe":
                        Recipes.Add(new PillRecipeInfo { Id = id, Name = p[2], Tier = int.Parse(p[3]), Element = int.Parse(p[4]), Category = p[5], Enabled = p[6] == "1", MaxUse = int.Parse(p[7]), ItemId = int.Parse(p[8]), Hint = p.Length > 9 ? p[9] : "", Source = p.Length > 10 ? p[10] : "" });
                        break;
                    case "effect":
                        Effects.Add(new PillEffectInfo { Id = id, Name = p[2], Tier = int.Parse(p[3]), Element = int.Parse(p[4]), Desc = p.Length > 5 ? p[5] : "" });
                        break;
                    case "ptalent":
                        {
                            var t = new PillTalentInfo { Id = id, Name = p[2], Phase = p[3], Desc = p[4] };
                            foreach (var lv in p[5].Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                var f = lv.Split(':');
                                t.Levels.Add(new PillTalentLevel { Rank = int.Parse(f[0]), Value = f[1], Cost = int.Parse(f[2]), ReqLevel = int.Parse(f[3]) });
                            }
                            Talents.Add(t);
                            break;
                        }
                }
            }
        }
    }

    public class NpcSlotEditItem
    {
        public int SlotId;
        public int TalentId;
        public bool Unlocked;
    }

    public class NpcPendingEdit
    {
        public int NpcId;
        public int Intimacy;
        public List<NpcSlotEditItem> Slots = new List<NpcSlotEditItem>();
    }

    public class SaveSlotEntry
    {
        public string SlotFolder;
        public string GameWorldPath;
        public string MetaPath;
        public string SlotName;
        public string CharacterName = "未知角色";
        public string RealmText = "";
        public string GameTimeText = "";
        public string SaveTimeText = "";

        public override string ToString()
        {
            return string.Format("[{0}] {1} | {2} | {3} ({4})",
                SlotName, CharacterName,
                string.IsNullOrEmpty(RealmText) ? "未知境界" : RealmText,
                GameTimeText, SaveTimeText);
        }
    }

    // =========================================================================
    // 5. 主窗口 UI
    // =========================================================================
    public class MainForm : Form
    {
        private ComboBox cmbSlots;
        private Button btnRefreshSlots;
        private Button btnBrowseSlot;
        private Button btnBackupNow;
        private Button btnRestoreBackup;
        private Button btnTopSaveNow;
        private Button btnSaveChanges;
        private CheckBox chkAutoLockEdits;
        private bool warnedGameRunning = false;
        private Label lblStatus;
        private Timer liveWatchTimer;

        // 道途与角色属性页控件
        private Label lblPlayerSummary;
        private NumericUpDown numPathPoints;
        private ListBox lstLearnedNodes;
        private Button btnResetDaoPath;
        private NumericUpDown numSpiritPoints;
        private Button btnResetSpiritRoots;
        private Label lblSpiritSummary;
        private NumericUpDown numAlignment;
        private Label lblAlignmentInfo;
        private NumericUpDown numCharm;
        private Label lblCharmInfo;
        private NumericUpDown[] numExplore = new NumericUpDown[5];
        private Label[] lblExploreLv = new Label[5];
        private Label lblExploreInfo;
        private NumericUpDown numDemonQi;
        private Label lblDemonQiInfo;
        private CheckBox chkDemonQiForce;

        // 背包物品页控件
        private ListView lvBag;
        private NumericUpDown numBagCount;
        private Label lblBagSummary;
        private TextBox txtSearchItem;
        private ComboBox cmbItemBag;
        private CheckBox chkShowUnverified;
        private ListView lvAddItems;
        private Label lblItemDesc;
        private NumericUpDown numAddCount;
        private Label lblPillGrade;
        private ComboBox cmbPillGrade;

        // NPC 天赋修改页控件
        private TextBox txtSearchNpc;
        private CheckBox chkOnlyCompanion;
        private CheckBox chkOnlyInSave;
        private ListView lvNpcs;

        private Label lblNpcTitle;
        private TextBox txtNpcSheetRef;
        private NumericUpDown numNpcIntimacy;

        private TextBox txtFilterTalent;
        private ComboBox cmbFilterQuality;
        private CheckBox[] chkSlotEnabled = new CheckBox[4];
        // 游戏配置里"固定天赋"的槽位（InitType = 0）不允许修改天赋
        private bool[] slotFixed = new bool[4];
        private int[] slotFixedTalentId = new int[4];
        private bool[] slotFixedInSave = new bool[4];   // 固定槽在存档里是否已经生成
        private ComboBox[] cmbSlotTalent = new ComboBox[4];
        private CheckBox[] chkSlotUnlocked = new CheckBox[4];
        private Label[] lblSlotDesc = new Label[4];
        private Button btnUnlockAllSlots;
        private Button btnRestoreDefaultSlots;
        private Button btnApplyNpc;

        // 当前加载的存档状态与持续锁定队列
        private SaveSlotEntry currentSlot;
        private bool currentWasEncrypted = true;
        private MsgPackNode rootNode;
        private Dictionary<int, MsgPackNode> saveNpcMap = new Dictionary<int, MsgPackNode>();
        // 只记录 NPC 天赋修改，用于"后台锁定"时重新套用；道途/灵根是一次性操作，绝不自动重复执行
        private Dictionary<int, NpcPendingEdit> lockedNpcEdits = new Dictionary<int, NpcPendingEdit>();

        private int selectedNpcId = -1;
        private List<TalentInfo> filteredTalents = new List<TalentInfo>();
        private DateTime lastKnownDiskWriteUtc = DateTime.MinValue;
        private bool isWritingDisk = false;

        public MainForm()
        {
            Text = "不问凡尘 · 存档修改器 v1.0";
            Size = new Size(1440, 900);
            MinimumSize = new Size(1280, 800);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Regular);

            BuildUI();
            ScanDefaultSaveSlots();

            liveWatchTimer = new Timer { Interval = 1800 };
            liveWatchTimer.Tick += OnLiveWatchTimerTick;
            liveWatchTimer.Tick += (s, e) => UpdateGameStateIndicator();
            liveWatchTimer.Start();
        }

        // =========================================================================
        // 界面：深色标题栏 + 工具栏 + 左侧分组导航 + 隐藏页签的主区域 + 底部状态栏
        // =========================================================================
        private static readonly Color ThemeInk = Color.FromArgb(30, 42, 56);
        private static readonly Color ThemeSide = Color.FromArgb(36, 52, 71);
        private static readonly Color ThemeSideHover = Color.FromArgb(48, 69, 94);
        private static readonly Color ThemeGold = Color.FromArgb(201, 160, 99);
        private static readonly Color ThemePage = Color.FromArgb(245, 246, 248);
        private static readonly Color ThemeGreen = Color.FromArgb(34, 125, 85);
        private static readonly Color ThemeBorder = Color.FromArgb(168, 178, 192);

        private Label lblHeaderSub;
        private Label lblGameVersion;
        private Label lblGameState;
        private readonly List<KeyValuePair<Button, TabPage>> navItems = new List<KeyValuePair<Button, TabPage>>();

        private void BuildUI()
        {
            BackColor = ThemePage;

            // ---------- 标题栏 ----------
            var pnlHeader = new Panel { Dock = DockStyle.Top, Height = 58, BackColor = ThemeInk };
            var lblTitle = new Label
            {
                Text = "不问凡尘 · 存档修改器",
                Location = new Point(18, 8), AutoSize = true, ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 15f, FontStyle.Bold)
            };
            var lblVer = new Label { Text = "v1.0", Location = new Point(236, 18), AutoSize = true, ForeColor = ThemeGold, Font = new Font("Microsoft YaHei UI", 10f, FontStyle.Bold) };
            lblHeaderSub = new Label { Text = "尚未加载存档", Location = new Point(290, 12), AutoSize = true, ForeColor = Color.FromArgb(190, 200, 212), Font = new Font("Microsoft YaHei UI", 10f) };
            lblGameState = new Label
            {
                Text = "", AutoSize = false, Size = new Size(190, 26), TextAlign = ContentAlignment.MiddleCenter,
                Anchor = AnchorStyles.Top | AnchorStyles.Right, Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold)
            };
            DetectInstalledGameVersion();
            bool outdated = installedSteamBuild > 0 && installedSteamBuild != TargetSteamBuild;
            lblGameVersion = new Label { Text = VersionHeaderText(), Location = new Point(292, 36), AutoSize = true, ForeColor = outdated ? Color.FromArgb(255, 196, 120) : Color.FromArgb(150, 165, 182), Font = new Font("Microsoft YaHei UI", 8.5f, outdated ? FontStyle.Bold : FontStyle.Regular) };
            pnlHeader.Controls.AddRange(new Control[] { lblTitle, lblVer, lblHeaderSub, lblGameState, lblGameVersion });
            pnlHeader.Resize += (s, e) => lblGameState.Location = new Point(pnlHeader.Width - lblGameState.Width - 16, 16);

            // ---------- 工具栏 ----------
            var pnlTop = new Panel { Dock = DockStyle.Top, Height = 50, BackColor = Color.White, Padding = new Padding(12, 0, 12, 0) };
            pnlTop.Paint += (s, e) => e.Graphics.DrawLine(new Pen(ThemeBorder), 0, pnlTop.Height - 1, pnlTop.Width, pnlTop.Height - 1);
            var lblSlot = new Label { Text = "当前存档：", Location = new Point(14, 16), AutoSize = true, Font = new Font(Font, FontStyle.Bold), ForeColor = ThemeInk };
            cmbSlots = new ComboBox { Location = new Point(88, 12), Width = 470, DropDownStyle = ComboBoxStyle.DropDownList };
            cmbSlots.SelectedIndexChanged += (s, e) => LoadSelectedSlot(false);
            btnRefreshSlots = new Button { Text = "刷新存档列表", Location = new Point(568, 10), Size = new Size(108, 30) };
            btnRefreshSlots.Click += (s, e) => ScanDefaultSaveSlots();
            btnBrowseSlot = new Button { Text = "手动选档…", Location = new Point(682, 10), Size = new Size(90, 30) };
            btnBrowseSlot.Click += (s, e) => BrowseSaveFile();
            btnBackupNow = new Button { Text = "备份此档", Location = new Point(778, 10), Size = new Size(84, 30) };
            btnBackupNow.Click += (s, e) => ManualBackupCurrentSlot();
            btnRestoreBackup = new Button { Text = "还原备份…", Location = new Point(868, 10), Size = new Size(90, 30) };
            btnRestoreBackup.Click += (s, e) => RestoreFromBackup();
            btnUndo = new Button { Text = "撤销上一次修改", Location = new Point(964, 10), Size = new Size(150, 30), Enabled = false };
            btnUndo.Click += (s, e) => UndoLastChange();
            btnTopSaveNow = new Button
            {
                Text = "保存到选中存档", Size = new Size(150, 32), Anchor = AnchorStyles.Top | AnchorStyles.Right,
                BackColor = ThemeGreen, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font(Font, FontStyle.Bold)
            };
            btnTopSaveNow.Click += (s, e) => WriteCurrentSaveImmediately(true);
            pnlTop.Controls.AddRange(new Control[] { lblSlot, cmbSlots, btnRefreshSlots, btnBrowseSlot, btnBackupNow, btnRestoreBackup, btnUndo, btnTopSaveNow });
            pnlTop.Resize += (s, e) => btnTopSaveNow.Location = new Point(pnlTop.Width - btnTopSaveNow.Width - 14, 9);

            // 后台锁定开关放到【使用教程】页的高级设置里
            chkAutoLockEdits = new CheckBox
            {
                Text = "后台锁定 NPC 天赋：游戏开着时，若游戏重新写入了当前选中的存档，自动把已改的 NPC 天赋再写回去（不动道途/灵根/好感，也不碰其他存档）",
                AutoSize = true, Checked = false, ForeColor = Color.FromArgb(35, 70, 135)
            };

            // ---------- 底部状态栏 ----------
            var pnlBottom = new Panel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(14, 6, 14, 6), BackColor = Color.White };
            pnlBottom.Paint += (s, e) => e.Graphics.DrawLine(new Pen(ThemeBorder), 0, 0, pnlBottom.Width, 0);
            btnSaveChanges = new Button
            {
                Text = "保存到选中存档（自动备份）", Dock = DockStyle.Right, Width = 240,
                BackColor = ThemeGreen, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font(Font.FontFamily, 10f, FontStyle.Bold)
            };
            btnSaveChanges.Click += (s, e) => WriteCurrentSaveImmediately(true);
            lblStatus = new Label { Text = "就绪。", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font(Font, FontStyle.Bold), ForeColor = Color.FromArgb(25, 55, 105) };
            pnlBottom.Controls.Add(lblStatus);
            pnlBottom.Controls.Add(btnSaveChanges);

            // ---------- 主区域（隐藏页签头，用左侧导航切换） ----------
            var tabs = new TabControl { Dock = DockStyle.Fill, Appearance = TabAppearance.FlatButtons, ItemSize = new Size(0, 1), SizeMode = TabSizeMode.Fixed };
            mainTabs = tabs;
            var tabHelp = new TabPage("使用教程");
            var tabNpc = new TabPage("NPC 天赋"); npcTabPage = tabNpc;
            var tabComp = new TabPage("同道 / 道侣 / 洞府");
            var tabDao = new TabPage("道途 / 灵根 / 善恶 / 魅力 / 魔气");
            var tabAttr = new TabPage("属性 / 精力");
            var tabLearn = new TabPage("功法心法");
            var tabBag = new TabPage("背包物品");
            var tabArt = new TabPage("法宝词条");
            var tabAlchemy = new TabPage("炼丹 / 炼器");
            var tabRep = new TabPage("声望 / 货币 / 迷雾 / 难度");
            var tabCompare = new TabPage("存档对比");
            var tabDonate = new TabPage("支持作者");

            BuildNpcTab(tabNpc);
            BuildCompanionTab(tabComp);
            BuildDaoTab(tabDao);
            BuildAttrTab(tabAttr);
            BuildLearnTab(tabLearn);
            BuildBagTab(tabBag);
            BuildArtifactTab(tabArt);
            BuildRepTab(tabRep);          // 要在炼丹页之前（炼丹/炼器分组从这里移过去）
            BuildAlchemyTab(tabAlchemy);
            BuildHelpTab(tabHelp);
            BuildCompareTab(tabCompare);
            BuildDonateTab(tabDonate);

            foreach (var tp in new[] { tabHelp, tabNpc, tabComp, tabDao, tabAttr, tabLearn, tabBag, tabArt, tabAlchemy, tabRep, tabCompare, tabDonate })
            {
                tp.BackColor = ThemePage;
                tp.Padding = new Padding(6);
                tabs.TabPages.Add(tp);
            }

            // ---------- 左侧导航 ----------
            var nav = new Panel { Dock = DockStyle.Left, Width = 196, BackColor = ThemeSide, Padding = new Padding(0, 8, 0, 8), AutoScroll = true };
            var groups = new List<KeyValuePair<string, KeyValuePair<string, TabPage>[]>>
            {
                new KeyValuePair<string, KeyValuePair<string, TabPage>[]>("开始", new[] { P("◆  使用教程", tabHelp), P("⇄  存档对比", tabCompare) }),
                new KeyValuePair<string, KeyValuePair<string, TabPage>[]>("人物", new[] { P("★  NPC 天赋", tabNpc), P("♥  同道 / 道侣 / 洞府", tabComp) }),
                new KeyValuePair<string, KeyValuePair<string, TabPage>[]>("修炼", new[] { P("☯  道途 / 灵根 / 善恶", tabDao), P("▲  属性 / 精力", tabAttr), P("✎  功法心法", tabLearn) }),
                new KeyValuePair<string, KeyValuePair<string, TabPage>[]>("物品", new[] { P("▣  背包物品", tabBag), P("⚔  法宝词条", tabArt) }),
                new KeyValuePair<string, KeyValuePair<string, TabPage>[]>("炼丹与经营", new[] { P("⚗  炼丹 / 炼器", tabAlchemy), P("⌂  声望 / 货币 / 难度", tabRep) }),
                new KeyValuePair<string, KeyValuePair<string, TabPage>[]>("其他", new[] { P("♡  支持作者", tabDonate) }),
            };
            int y = 8;
            var navControls = new List<Control>();
            foreach (var g in groups)
            {
                navControls.Add(new Label { Text = g.Key, Location = new Point(18, y), AutoSize = true, ForeColor = Color.FromArgb(130, 148, 170), Font = new Font("Microsoft YaHei UI", 8.5f, FontStyle.Bold) });
                y += 22;
                foreach (var item in g.Value)
                {
                    var b = new Button
                    {
                        Text = item.Key, Location = new Point(8, y), Size = new Size(180, 36), TextAlign = ContentAlignment.MiddleLeft,
                        FlatStyle = FlatStyle.Flat, ForeColor = Color.FromArgb(214, 221, 230), BackColor = ThemeSide,
                        Font = new Font("Microsoft YaHei UI", 10f), Padding = new Padding(8, 0, 0, 0), Cursor = Cursors.Hand, Tag = "nav"
                    };
                    b.FlatAppearance.BorderSize = 0;
                    b.FlatAppearance.MouseOverBackColor = ThemeSideHover;
                    var page = item.Value;
                    b.Click += (s, e) => tabs.SelectedTab = page;
                    navItems.Add(new KeyValuePair<Button, TabPage>(b, page));
                    navControls.Add(b);
                    y += 40;
                }
                y += 10;
            }
            nav.Controls.AddRange(navControls.ToArray());
            tabs.SelectedIndexChanged += (s, e) => UpdateNavHighlight();

            Controls.Add(tabs);
            Controls.Add(nav);
            Controls.Add(pnlBottom);
            Controls.Add(pnlTop);
            Controls.Add(pnlHeader);

            ApplyTheme(this);
            UpdateNavHighlight();
            UpdateGameStateIndicator();
        }

        private static KeyValuePair<string, TabPage> P(string text, TabPage page) { return new KeyValuePair<string, TabPage>(text, page); }

        private void UpdateNavHighlight()
        {
            foreach (var kv in navItems)
            {
                bool on = mainTabs.SelectedTab == kv.Value;
                kv.Key.BackColor = on ? ThemeGold : ThemeSide;
                kv.Key.ForeColor = on ? ThemeInk : Color.FromArgb(214, 221, 230);
                kv.Key.Font = new Font("Microsoft YaHei UI", 10f, on ? FontStyle.Bold : FontStyle.Regular);
                kv.Key.FlatAppearance.MouseOverBackColor = on ? ThemeGold : ThemeSideHover;
            }
        }

        private void UpdateGameStateIndicator()
        {
            if (lblGameState == null) return;
            bool running = IsGameRunning();
            lblGameState.Text = running ? "● 游戏正在运行" : "● 游戏未运行";
            lblGameState.ForeColor = running ? Color.FromArgb(255, 196, 120) : Color.FromArgb(140, 220, 170);
            lblGameState.BackColor = running ? Color.FromArgb(70, 48, 30) : Color.FromArgb(28, 64, 50);
        }

        private void UpdateHeaderInfo()
        {
            if (lblHeaderSub == null) return;
            if (currentSlot == null) { lblHeaderSub.Text = "尚未加载存档"; return; }
            lblHeaderSub.Text = string.Format("{0}　·　{1}　·　{2}　·　存档 {3}",
                currentSlot.CharacterName, string.IsNullOrEmpty(currentSlot.RealmText) ? "未知境界" : currentSlot.RealmText,
                currentSlot.GameTimeText, currentSlot.SlotName);
        }

        // 去掉按钮/复选框里显示成方块的彩色表情（代理对字符和变体选择符）
        private static string StripColorEmoji(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { i++; continue; }
                if (c == '️' || c == '‍') continue;
                sb.Append(c);
            }
            return sb.ToString().Trim();
        }

        private void ApplyTheme(Control root)
        {
            foreach (Control c in root.Controls)
            {
                var b = c as Button;
                if (b != null && !"nav".Equals(b.Tag))
                {
                    b.Text = StripColorEmoji(b.Text);
                    b.FlatStyle = FlatStyle.Flat;
                    b.Cursor = Cursors.Hand;
                    bool colored = b.BackColor != SystemColors.Control && b.BackColor != Color.Empty && b.BackColor.ToArgb() != SystemColors.Control.ToArgb();
                    if (colored)
                    {
                        if (b.BackColor.G > b.BackColor.R && b.BackColor.G > b.BackColor.B) b.BackColor = ThemeGreen;
                        b.FlatAppearance.BorderSize = 0;
                        b.FlatAppearance.MouseOverBackColor = ControlPaint.Light(b.BackColor, 0.15f);
                    }
                    else
                    {
                        b.BackColor = Color.White;
                        b.ForeColor = ThemeInk;
                        b.FlatAppearance.BorderColor = ThemeBorder;
                        b.FlatAppearance.BorderSize = 1;
                        b.FlatAppearance.MouseOverBackColor = Color.FromArgb(236, 241, 247);
                    }
                }
                var cb = c as CheckBox;
                if (cb != null) cb.Text = StripColorEmoji(cb.Text);
                var gb = c as GroupBox;
                if (gb != null) gb.Text = StripColorEmoji(gb.Text);
                var tp = c as TabPage;
                if (tp != null && tp.Parent != mainTabs) tp.BackColor = ThemePage;
                var lv = c as ListView;
                if (lv != null) lv.BorderStyle = BorderStyle.FixedSingle;
                if (c.HasChildren) ApplyTheme(c);
            }
        }

        // ---------- 使用教程页 ----------
        private void BuildHelpTab(TabPage tab)
        {
            var rtb = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 10.5f), DetectUrls = false, ScrollBars = RichTextBoxScrollBars.Vertical
            };
            var adv = new Panel { Dock = DockStyle.Bottom, Height = 70, BackColor = Color.White, Padding = new Padding(16, 6, 16, 6) };
            var lblAdv = new Label { Text = "高级设置", Location = new Point(16, 8), AutoSize = true, Font = new Font(Font, FontStyle.Bold), ForeColor = ThemeInk };
            chkAutoLockEdits.Location = new Point(16, 34);
            adv.Controls.AddRange(new Control[] { lblAdv, chkAutoLockEdits });
            adv.Paint += (s, e) => e.Graphics.DrawLine(new Pen(ThemeBorder), 0, 0, adv.Width, 0);

            var wrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(24, 16, 24, 8), BackColor = Color.White };
            wrap.Controls.Add(rtb);
            tab.Controls.Add(wrap);
            tab.Controls.Add(adv);

            Action<string> H1 = t => { rtb.SelectionFont = new Font("Microsoft YaHei UI", 16f, FontStyle.Bold); rtb.SelectionColor = ThemeInk; rtb.AppendText(t + "\n"); };
            Action<string> H2 = t => { rtb.SelectionFont = new Font("Microsoft YaHei UI", 12.5f, FontStyle.Bold); rtb.SelectionColor = Color.FromArgb(150, 110, 50); rtb.AppendText("\n" + t + "\n"); };
            Action<string> Pa = t => { rtb.SelectionFont = new Font("Microsoft YaHei UI", 10.5f); rtb.SelectionColor = Color.FromArgb(50, 58, 70); rtb.AppendText(t + "\n"); };
            Action<string, string> Item = (k, v) =>
            {
                rtb.SelectionFont = new Font("Microsoft YaHei UI", 10.5f, FontStyle.Bold); rtb.SelectionColor = ThemeInk; rtb.AppendText("  " + k + "　");
                rtb.SelectionFont = new Font("Microsoft YaHei UI", 10.5f); rtb.SelectionColor = Color.FromArgb(50, 58, 70); rtb.AppendText(v + "\n");
            };

            H1("使用教程");
            Pa("这个工具直接修改《不问凡尘》的本地存档文件，不会注入游戏。每次写入前都会自动备份，改坏了可以随时还原。");

            H2("适配版本");
            Item("游戏版本", string.Format("这个修改器按《不问凡尘》Steam Build {0}（{1} 更新）、存档格式 {2} 制作。", TargetSteamBuild, TargetGameDate, TargetSaveVersion));
            Item("游戏更新后", "右上角标题栏会显示\"游戏已更新\"。新版本里新增的物品、丹方等不会出现在列表里，个别功能也可能不准，改之前记得备份，并留意修改器的更新。");

            H2("一、三步上手");
            Item("① 关掉游戏", "最稳妥。游戏开着时，它下次自动存档可能会把你的修改覆盖掉。");
            Item("② 选一个存档", "在上方【当前存档】下拉框里选。推荐选手动存档（manual_xx），自动存档（auto）会被游戏轮流覆盖。");
            Item("③ 修改并写入", "在左侧选一个功能页修改。绝大多数按钮点一下就会立刻写入存档（并自动备份），不需要再另外点保存。");
            Item("④ 进游戏读档", "打开游戏，读取你刚才改的那个存档，就能看到效果。");

            H2("二、安全须知");
            Item("自动备份", "每次写入前，原存档会备份到【文档\\WorldApartSaveEditor_Backups】。第一次修改前的原档永久保留，另外保留最近 20 份。");
            Item("撤销上一次修改", "上方【撤销上一次修改】按钮会把当前存档退回到最近一次修改之前，可以连续点、一步步往回退（只记这次打开编辑器后的修改）。");
            Item("还原备份", "点上方【还原备份…】，选一个备份里的 gameworld.msgpack 即可恢复。");
            Item("只写一个存档", "工具只会写入上方选中的那一个存档，不会动其他存档。");
            Item("游戏开着时", "右上角会显示\"游戏正在运行\"。这时写入会先弹出提醒；写完要马上在游戏里读取这个存档。");

            H2("三、各功能页说明");
            Item("NPC 天赋", "修改 NPC 的天赋槽、好感（满好感 500）、境界和寿元。标\"固定天赋\"的槽位是游戏设定，不能更换；\"随机天赋\"可以自由改。");
            Item("同道 / 道侣 / 洞府", "游戏里同道、道侣（结缘）是两种关系：同道有人数上限（炼气3/筑基5/结丹10/元婴15/化神20），NPC 天赋要结为同道才生效；道侣是结缘关系。这页可以结为/解除同道、结缘/解除结缘、设主道侣、安排洞府（小重天·仙居楼）5 间房的住客，还能批量满好感、批量解锁天赋槽。双击某人可跳到 NPC 天赋页编辑。");
            Item("道途 / 灵根 / 善恶", "道途点、灵根点重置与修改，善恶值、魅力值、魔气值，五项探索属性（灵机、体魄、神识、辩道、医术）。");
            Item("属性 / 精力", "给攻击、防御、速度、暴击等属性加\"存档修改器\"加成（和吃果子的加成一样），可随时清除；修改当前精力。");
            Item("功法心法", "直接学会有秘籍的功法和心法（学心法时会和游戏一样建好技能槽）。");
            Item("背包物品", "添加物品、修改数量、删除物品。功法秘籍、丹药、未炼制法宝、璞石也能添加；任务物品会先确认。");
            Item("法宝词条", "修改法宝主属性和词条、改品阶、加词条槽、清除洗练待确认的词条。");
            Item("炼丹 / 炼器", "丹方图鉴（查漏补缺、来源提示、改药效词条、补录）、炼丹等级、丹炉、炼丹天赋、丹药服用次数重置；炼器等级与炼器天赋。");
            Item("声望 / 货币 / 难度", "灵石、宗门贡献、城镇贡献、15 个城镇和 10 个宗门的声望，地图迷雾全开，修改游戏难度（简单 / 困难 / 极难 / 地狱 / 灭世；灭世死亡会删档，会二次确认）。");

            Item("存档对比", "选两个存档（也可以选备份），列出哪里不一样。想改一个新东西时：在游戏里做这件事前后各存一次档，拿来一比，就知道它改了存档的哪里。");
            H2("四、常见问题");
            Item("改了没生效？", "确认改的是你在游戏里读取的那个存档；游戏开着时要重新读档。道途、天赋、装备带来的加成是游戏实时算的，编辑器里看不到。");
            Item("标着\"未验证\"是什么？", "这类物品/格式在你的存档里没出现过，无法 100% 确认格式，添加前会提醒，出问题可还原备份。");
            Item("丹方的来源提示准吗？", "丹方图鉴里选【只看炼丹秘境的丹方】，就只显示能在炼丹地图里找到的。来源取自游戏配置里物品的获取途径：标\"炼丹秘境\"的在炼丹地图里找；标\"奇遇获得\"或\"诸天开藏/百机堂\"的不在炼丹地图上。");
            Item("魔气值为什么不能改？", "要先在道途里学会魔修【吞魄入魔】。魔气达到上限会走火入魔、进入【堕入魔界】结局，所以最多只能设到上限减 1。");
            Item("存档时间显示 1970 年？", "那是旧版本（Gemini 版）的问题，新版本已修复。在游戏里重新存一次档即可。");

            rtb.SelectionStart = 0;
            rtb.ScrollToCaret();
        }

        private void BuildNpcTab(TabPage tab)
        {
            var split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
            Shown += (s, e) => { try { split.SplitterDistance = 500; } catch { } };

            // 左侧：NPC 搜索与列表
            var pnlLeft = split.Panel1;
            pnlLeft.Padding = new Padding(8);

            var lblSearch = new Label { Text = "搜索姓名/称号/ID/天赋：", Location = new Point(10, 14), AutoSize = true };
            txtSearchNpc = new TextBox { Location = new Point(175, 10), Width = 215 };
            txtSearchNpc.TextChanged += (s, e) => RefreshNpcListView();

            var btnClearSearch = new Button { Text = "清空", Location = new Point(396, 9), Size = new Size(56, 26) };
            btnClearSearch.Click += (s, e) => txtSearchNpc.Text = "";

            chkOnlyCompanion = new CheckBox { Text = "仅显示可结缘角色", Location = new Point(12, 42), AutoSize = true };
            chkOnlyCompanion.CheckedChanged += (s, e) => RefreshNpcListView();

            chkOnlyInSave = new CheckBox { Text = "仅显示当前存档已生成角色", Location = new Point(190, 42), AutoSize = true, Checked = true };
            chkOnlyInSave.CheckedChanged += (s, e) => RefreshNpcListView();

            lvNpcs = new ListView
            {
                Location = new Point(10, 70),
                Size = new Size(pnlLeft.Width - 20, pnlLeft.Height - 80),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                MultiSelect = false
            };
            lvNpcs.Columns.Add("NPC ID", 68);
            lvNpcs.Columns.Add("姓名", 78);
            lvNpcs.Columns.Add("称号", 105);
            lvNpcs.Columns.Add("可结缘", 52);
            lvNpcs.Columns.Add("好感", 48);
            lvNpcs.Columns.Add("当前存档天赋 (✔=已解锁)", 260);
            lvNpcs.SelectedIndexChanged += (s, e) =>
            {
                if (lvNpcs.SelectedItems.Count > 0)
                {
                    int nid = (int)lvNpcs.SelectedItems[0].Tag;
                    SelectNpc(nid);
                }
            };

            pnlLeft.Controls.AddRange(new Control[] { lblSearch, txtSearchNpc, btnClearSearch, chkOnlyCompanion, chkOnlyInSave, lvNpcs });

            // 右侧：NPC 天赋详情与 4 槽位编辑
            var pnlRight = split.Panel2;
            pnlRight.Padding = new Padding(12);
            pnlRight.AutoScroll = true;

            lblNpcTitle = new Label
            {
                Text = "请在左侧列表中选择一个 NPC 角色",
                Location = new Point(12, 10),
                AutoSize = true,
                Font = new Font(Font.FontFamily, 12f, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 65, 120)
            };

            var lblIntimacy = new Label { Text = "当前好感度：", Location = new Point(420, 14), AutoSize = true };
            numNpcIntimacy = new NumericUpDown { Location = new Point(510, 10), Width = 85, Minimum = -9999, Maximum = MaxIntimacy, Value = 0 };
            var btnMaxIntimacy = new Button { Text = "满好感(500)", Location = new Point(602, 9), Size = new Size(98, 26) };
            btnMaxIntimacy.Click += (s, e) => numNpcIntimacy.Value = MaxIntimacy;

            txtNpcSheetRef = new TextBox
            {
                Location = new Point(12, 42),
                Size = new Size(690, 56),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(250, 250, 242),
                Text = "参考表信息将显示在这里..."
            };

            // 词条筛选工具条
            var grpFilter = new GroupBox
            {
                Text = "🔎 天赋下拉框快速筛选（筛选后在下方各槽位下拉框中选择）",
                Location = new Point(12, 104),
                Size = new Size(690, 56)
            };
            var lblFQ = new Label { Text = "品质筛选：", Location = new Point(12, 24), AutoSize = true };
            cmbFilterQuality = new ComboBox { Location = new Point(86, 20), Width = 140, DropDownStyle = ComboBoxStyle.DropDownList };
            cmbFilterQuality.Items.AddRange(new object[] {
                "全部品质 (130)",
                "5 - 仙品·红",
                "4 - 极品·金",
                "3 - 上品·紫",
                "2 - 良品·蓝",
                "1 - 凡品·绿"
            });
            cmbFilterQuality.SelectedIndex = 0;
            cmbFilterQuality.SelectedIndexChanged += (s, e) => RebuildTalentDropdowns();

            var lblFK = new Label { Text = "关键字过滤(搜名称/效果)：", Location = new Point(242, 24), AutoSize = true };
            txtFilterTalent = new TextBox { Location = new Point(416, 20), Width = 190 };
            txtFilterTalent.TextChanged += (s, e) => RebuildTalentDropdowns();

            var btnResetFilter = new Button { Text = "重置", Location = new Point(614, 19), Size = new Size(62, 26) };
            btnResetFilter.Click += (s, e) => { cmbFilterQuality.SelectedIndex = 0; txtFilterTalent.Text = ""; };
            grpFilter.Controls.AddRange(new Control[] { lblFQ, cmbFilterQuality, lblFK, txtFilterTalent, btnResetFilter });

            // 4 个天赋槽编辑区
            int startY = 166;
            for (int i = 0; i < 4; i++)
            {
                int slotIdx = i;
                var grpSlot = new GroupBox
                {
                    Text = string.Format("天赋槽 {0}", i + 1),
                    Location = new Point(12, startY + i * 94),
                    Size = new Size(690, 86)
                };

                chkSlotEnabled[i] = new CheckBox
                {
                    Text = "启用此槽位",
                    Location = new Point(14, 24),
                    AutoSize = true,
                    Checked = true
                };
                chkSlotEnabled[i].CheckedChanged += (s, e) =>
                {
                    bool en = chkSlotEnabled[slotIdx].Checked;
                    cmbSlotTalent[slotIdx].Enabled = en && !slotFixed[slotIdx];
                    chkSlotUnlocked[slotIdx].Enabled = en;
                };

                cmbSlotTalent[i] = new ComboBox
                {
                    Location = new Point(115, 20),
                    Width = 455,
                    DropDownStyle = ComboBoxStyle.DropDownList,
                    DropDownWidth = 650
                };
                cmbSlotTalent[i].SelectedIndexChanged += (s, e) => UpdateSlotDescLabel(slotIdx);

                chkSlotUnlocked[i] = new CheckBox
                {
                    Text = "已解锁生效",
                    Location = new Point(580, 23),
                    AutoSize = true,
                    Checked = true,
                    Font = new Font(Font, FontStyle.Bold),
                    ForeColor = Color.FromArgb(20, 110, 50)
                };

                lblSlotDesc[i] = new Label
                {
                    Text = "当前未选择天赋",
                    Location = new Point(14, 52),
                    Size = new Size(660, 26),
                    ForeColor = Color.FromArgb(70, 70, 70)
                };

                grpSlot.Controls.AddRange(new Control[] { chkSlotEnabled[i], cmbSlotTalent[i], chkSlotUnlocked[i], lblSlotDesc[i] });
                pnlRight.Controls.Add(grpSlot);
            }

            // 底部操作按钮：点击后写入选中的存档
            int btnY = startY + 4 * 94 + 6;
            btnUnlockAllSlots = new Button
            {
                Text = "🔓 一键全解锁并直接写入存档",
                Location = new Point(12, btnY),
                Size = new Size(210, 38)
            };
            btnUnlockAllSlots.Click += (s, e) =>
            {
                for (int i = 0; i < 4; i++)
                    if (chkSlotEnabled[i].Checked) chkSlotUnlocked[i].Checked = true;
                ApplyCurrentNpcEditsAndWriteDisk(true);
            };

            btnRestoreDefaultSlots = new Button
            {
                Text = "🔄 恢复参考表默认配置",
                Location = new Point(230, btnY),
                Size = new Size(165, 38)
            };
            btnRestoreDefaultSlots.Click += (s, e) => RestoreSelectedNpcDefaultSlots();

            btnApplyNpc = new Button
            {
                Text = "应用此角色修改并写入存档",
                Location = new Point(403, btnY),
                Size = new Size(299, 38),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font(Font, FontStyle.Bold)
            };
            btnApplyNpc.Click += (s, e) => ApplyCurrentNpcEditsAndWriteDisk(true);

            // NPC 境界 / 寿元
            var grpRealm = new GroupBox { Text = "NPC 境界 / 寿元（单独写入）", Location = new Point(12, btnY + 46), Size = new Size(690, 64) };
            var lblLayer = new Label { Text = "境界：", Location = new Point(14, 28), AutoSize = true };
            cmbNpcLayer = new ComboBox { Location = new Point(60, 24), Width = 170, DropDownStyle = ComboBoxStyle.DropDownList, MaxDropDownItems = 20 };
            foreach (var li in MiscDatabase.Layers) cmbNpcLayer.Items.Add(li);
            var lblLife = new Label { Text = "寿元加成：", Location = new Point(244, 28), AutoSize = true };
            numNpcLifespan = new NumericUpDown { Location = new Point(316, 24), Width = 90, Minimum = -9999, Maximum = 99999 };
            var btnRealm = new Button { Text = "写入境界和寿元", Location = new Point(420, 21), Size = new Size(160, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnRealm.Click += (s, e) => SetNpcRealmAndWrite();
            grpRealm.Controls.AddRange(new Control[] { lblLayer, cmbNpcLayer, lblLife, numNpcLifespan, btnRealm });

            pnlRight.Controls.AddRange(new Control[] {
                lblNpcTitle, lblIntimacy, numNpcIntimacy, btnMaxIntimacy,
                txtNpcSheetRef, grpFilter,
                btnUnlockAllSlots, btnRestoreDefaultSlots, btnApplyNpc, grpRealm
            });

            RebuildTalentDropdowns();
            tab.Controls.Add(split);
        }

        private void BuildDaoTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20) };

            var grpDao = new GroupBox
            {
                Text = "🧘 玩家道途点重置与修改（点按钮即写入选中存档）",
                Location = new Point(20, 16),
                Size = new Size(640, 440)
            };

            lblPlayerSummary = new Label
            {
                Text = "请先在顶部加载一个存档槽位。",
                Location = new Point(20, 30),
                Size = new Size(600, 48),
                Font = new Font(Font.FontFamily, 10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(30, 65, 115)
            };

            var lblPts = new Label { Text = "当前可用道途点数 (talent_path_points)：", Location = new Point(20, 90), AutoSize = true };
            numPathPoints = new NumericUpDown { Location = new Point(305, 86), Width = 120, Minimum = 0, Maximum = 99999, Value = 0 };

            var btnApplyPts = new Button
            {
                Text = "修改道途点",
                Location = new Point(435, 84),
                Size = new Size(180, 30),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnApplyPts.Click += (s, e) => UpdatePlayerPathPointsOnly();

            var lblNodes = new Label { Text = "当前存档已点亮的道途节点列表 (tbtalentpathnode)：", Location = new Point(20, 128), AutoSize = true };
            lstLearnedNodes = new ListBox { Location = new Point(20, 152), Size = new Size(595, 215) };

            btnResetDaoPath = new Button
            {
                Text = "⚡ 一键重置道途（清空全部节点 + 全额返还道途点）",
                Location = new Point(20, 380),
                Size = new Size(595, 44),
                BackColor = Color.FromArgb(195, 85, 25),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font(Font.FontFamily, 10.5f, FontStyle.Bold)
            };
            btnResetDaoPath.Click += (s, e) => ResetPlayerDaoPath();

            grpDao.Controls.AddRange(new Control[] { lblPlayerSummary, lblPts, numPathPoints, btnApplyPts, lblNodes, lstLearnedNodes, btnResetDaoPath });

            var grpSpirit = new GroupBox
            {
                Text = "✨ 玩家灵根点重置与修改（点按钮即写入选中存档）",
                Location = new Point(680, 16),
                Size = new Size(500, 260)
            };

            lblSpiritSummary = new Label
            {
                Text = "当前各系灵根分配情况：未加载存档",
                Location = new Point(20, 32),
                Size = new Size(460, 75)
            };

            var lblSpRemain = new Label { Text = "当前剩余可用灵根点：", Location = new Point(20, 120), AutoSize = true };
            numSpiritPoints = new NumericUpDown { Location = new Point(185, 116), Width = 105, Minimum = 0, Maximum = 99999, Value = 0 };

            var btnUpdateSp = new Button
            {
                Text = "修改灵根点",
                Location = new Point(300, 114),
                Size = new Size(180, 30),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnUpdateSp.Click += (s, e) => UpdatePlayerSpiritPointsOnly();

            btnResetSpiritRoots = new Button
            {
                Text = "🔄 一键重置五系灵根（清空已加点数 + 全额返还）",
                Location = new Point(20, 175),
                Size = new Size(460, 44)
            };
            btnResetSpiritRoots.Click += (s, e) => ResetPlayerSpiritRoots();

            grpSpirit.Controls.AddRange(new Control[] { lblSpiritSummary, lblSpRemain, numSpiritPoints, btnUpdateSp, btnResetSpiritRoots });

            // ---- 善恶值 & 魅力值 ----
            var grpMisc = new GroupBox
            {
                Text = "⚖ 善恶值 && 魅力值 && 魔气值",
                Location = new Point(680, 290),
                Size = new Size(500, 318)
            };

            var lblAl = new Label { Text = "善恶值（正=善，负=恶）：", Location = new Point(20, 32), AutoSize = true };
            numAlignment = new NumericUpDown { Location = new Point(200, 28), Width = 110, Minimum = -999999, Maximum = 999999, Value = 0 };
            var btnAl = new Button
            {
                Text = "修改善恶值",
                Location = new Point(320, 26),
                Size = new Size(160, 30),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnAl.Click += (s, e) => SetAlignmentAndWrite();
            numAlignment.ValueChanged += (s, e) =>
            {
                long g, ev;
                GetAlignmentParts(out g, out ev);
                long cur = g + ev;
                if ((long)numAlignment.Value == cur) return;
                lblAlignmentInfo.Text = string.Format("当前 {0}（善值 {1} + 恶值 {2}）→ 改为 {3}，对应称号：{4}\r\n（≤-2000 万夫所指 / ≤-1000 臭名昭著 / ±999 无名之辈 / ≥1000 乐善好施 / ≥2000 德高望重）",
                    cur, g, ev, (long)numAlignment.Value, AlignmentTitle((long)numAlignment.Value));
            };
            lblAlignmentInfo = new Label { Location = new Point(20, 60), Size = new Size(465, 36), ForeColor = Color.FromArgb(45, 75, 110) };

            var lblCh = new Label { Text = "魅力值（存档内合计）：", Location = new Point(20, 112), AutoSize = true };
            numCharm = new NumericUpDown { Location = new Point(200, 108), Width = 110, Minimum = -99999, Maximum = 99999, Value = 0 };
            var btnCh = new Button
            {
                Text = "修改魅力值",
                Location = new Point(320, 106),
                Size = new Size(160, 30),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnCh.Click += (s, e) => SetCharmAndWrite();
            lblCharmInfo = new Label { Location = new Point(20, 140), Size = new Size(465, 58), ForeColor = Color.FromArgb(45, 75, 110) };

            var lblDq = new Label { Text = "魔气值（层）：", Location = new Point(20, 210), AutoSize = true };
            numDemonQi = new NumericUpDown { Location = new Point(200, 206), Width = 110, Minimum = 0, Maximum = 0, Value = 0 };
            var btnDq = new Button
            {
                Text = "修改魔气值",
                Location = new Point(320, 204),
                Size = new Size(160, 30),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnDq.Click += (s, e) => SetDemonQiAndWrite();
            chkDemonQiForce = new CheckBox { Text = "我知道风险：没学【吞魄入魔】也强行修改（最多 249）", Location = new Point(20, 238), AutoSize = true, ForeColor = Color.FromArgb(170, 70, 20), Visible = false };
            chkDemonQiForce.CheckedChanged += (s, e) => RefreshAlignmentCharmUI();
            lblDemonQiInfo = new Label { Location = new Point(20, 262), Size = new Size(465, 50), ForeColor = Color.FromArgb(45, 75, 110) };

            grpMisc.Controls.AddRange(new Control[] { lblAl, numAlignment, btnAl, lblAlignmentInfo, lblCh, numCharm, btnCh, lblCharmInfo,
                lblDq, numDemonQi, btnDq, chkDemonQiForce, lblDemonQiInfo });

            // ---- 五项探索属性 ----
            var grpExplore = new GroupBox
            {
                Text = "🧭 五项探索属性（填的是累计经验值）",
                Location = new Point(20, 464),
                Size = new Size(640, 136)
            };
            for (int i = 0; i < 5; i++)
            {
                var lbl = new Label { Text = ExploreNames[i], Location = new Point(14 + i * 124, 28), AutoSize = true };
                numExplore[i] = new NumericUpDown { Location = new Point(50 + i * 124, 24), Width = 72, Minimum = 0, Maximum = 99999 };
                numExplore[i].ValueChanged += (s, e) => UpdateExploreInfo();
                lblExploreLv[i] = new Label { Location = new Point(50 + i * 124, 52), AutoSize = true, ForeColor = Color.FromArgb(45, 75, 110) };
                grpExplore.Controls.Add(lblExploreLv[i]);
                grpExplore.Controls.Add(lbl);
                grpExplore.Controls.Add(numExplore[i]);
            }
            var btnExplore = new Button
            {
                Text = "修改五项属性",
                Location = new Point(14, 82),
                Size = new Size(140, 30),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnExplore.Click += (s, e) => SetExploreAndWrite();
            var btnExploreMax = new Button { Text = "全部填 5700(满级)", Location = new Point(160, 82), Size = new Size(130, 30) };
            btnExploreMax.Click += (s, e) => { for (int i = 0; i < 5; i++) numExplore[i].Value = ExploreLevelExp[ExploreLevelExp.Length - 1]; };
            lblExploreInfo = new Label { Location = new Point(300, 80), Size = new Size(334, 40), ForeColor = Color.FromArgb(45, 75, 110) };
            grpExplore.Controls.AddRange(new Control[] { btnExplore, btnExploreMax, lblExploreInfo });

            pnl.AutoScroll = true;
            pnl.Controls.AddRange(new Control[] { grpDao, grpSpirit, grpMisc, grpExplore });
            tab.Controls.Add(pnl);
        }

        // =========================================================================
        // 6. 存档扫描、读取、实时监控与一键直写逻辑
        // =========================================================================
        private void ScanDefaultSaveSlots()
        {
            cmbSlots.Items.Clear();
            string localLow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow", "Nuverse", "WorldApart", "StorageV1", "1.0");
            var entries = new List<SaveSlotEntry>();

            if (Directory.Exists(localLow))
            {
                foreach (var userDir in Directory.GetDirectories(localLow))
                {
                    string slotsRoot = Path.Combine(userDir, "slots");
                    if (!Directory.Exists(slotsRoot)) continue;
                    foreach (var slotDir in Directory.GetDirectories(slotsRoot))
                    {
                        string gwPath = Path.Combine(slotDir, "gameworld.msgpack");
                        if (!File.Exists(gwPath)) continue;
                        entries.Add(ReadSlotEntry(slotDir, gwPath));
                    }
                }
            }

            foreach (var e in entries.OrderByDescending(x => File.GetLastWriteTimeUtc(x.GameWorldPath)))
            {
                cmbSlots.Items.Add(e);
            }

            if (cmbSlots.Items.Count > 0)
            {
                cmbSlots.SelectedIndex = 0;
            }
            else
            {
                lblStatus.Text = "未在默认路径找到存档，请点击【手动选档...】定位 gameworld.msgpack。";
            }
        }

        private SaveSlotEntry ReadSlotEntry(string slotDir, string gwPath)
        {
            var entry = new SaveSlotEntry
            {
                SlotFolder = slotDir,
                GameWorldPath = gwPath,
                MetaPath = Path.Combine(slotDir, "meta.msgpack"),
                SlotName = Path.GetFileName(slotDir),
                SaveTimeText = File.GetLastWriteTime(gwPath).ToString("yyyy-MM-dd HH:mm:ss")
            };

            if (File.Exists(entry.MetaPath))
            {
                try
                {
                    bool enc;
                    byte[] rawMeta = File.ReadAllBytes(entry.MetaPath);
                    byte[] plainMeta = SimpleSaveCrypto.DecryptOrPassThrough(rawMeta, out enc);
                    var metaNode = MsgPackNode.Parse(plainMeta);
                    if (metaNode.Kind == MsgPackKind.Map)
                    {
                        var cn = metaNode.GetMapValue("characterName") ?? metaNode.GetMapValue("CharacterName");
                        var rl = metaNode.GetMapValue("cultivationLevelText") ?? metaNode.GetMapValue("CultivationLevelText");
                        var gt = metaNode.GetMapValue("gameTimeText") ?? metaNode.GetMapValue("GameTimeText");
                        if (cn != null && !string.IsNullOrEmpty(cn.AsString())) entry.CharacterName = cn.AsString();
                        if (rl != null && !string.IsNullOrEmpty(rl.AsString())) entry.RealmText = rl.AsString();
                        if (gt != null && !string.IsNullOrEmpty(gt.AsString())) entry.GameTimeText = gt.AsString();
                    }
                }
                catch { }
            }
            return entry;
        }

        private void BrowseSaveFile()
        {
            using (var ofd = new OpenFileDialog())
            {
                ofd.Title = "选择《不问凡尘》存档文件 gameworld.msgpack";
                ofd.Filter = "不问凡尘存档 (gameworld.msgpack)|gameworld.msgpack|所有 msgpack 文件 (*.msgpack)|*.msgpack|所有文件 (*.*)|*.*";
                string initDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow", "Nuverse", "WorldApart");
                if (Directory.Exists(initDir)) ofd.InitialDirectory = initDir;

                if (ofd.ShowDialog(this) == DialogResult.OK)
                {
                    string dir = Path.GetDirectoryName(ofd.FileName);
                    var entry = ReadSlotEntry(dir, ofd.FileName);
                    cmbSlots.Items.Insert(0, entry);
                    cmbSlots.SelectedIndex = 0;
                }
            }
        }

        private void LoadSelectedSlot(bool preserveLockedEdits)
        {
            var entry = cmbSlots.SelectedItem as SaveSlotEntry;
            if (entry == null) return;

            try
            {
                int prevSelectedNpc = selectedNpcId;
                byte[] rawBytes = File.ReadAllBytes(entry.GameWorldPath);
                byte[] plainBytes = SimpleSaveCrypto.DecryptOrPassThrough(rawBytes, out currentWasEncrypted);
                rootNode = MsgPackNode.Parse(plainBytes);
                currentSlot = entry;
                lastKnownDiskWriteUtc = File.GetLastWriteTimeUtc(entry.GameWorldPath);

                if (!preserveLockedEdits)
                    lockedNpcEdits.Clear();

                IndexSaveNpcs();

                if (preserveLockedEdits)
                {
                    ReapplyLockedEditsToRootNode();
                }

                RefreshDaoTabUI();
                RefreshNpcListView();

                if (prevSelectedNpc > 0 && saveNpcMap.ContainsKey(prevSelectedNpc))
                {
                    SelectNpc(prevSelectedNpc);
                }
                else if (lvNpcs.Items.Count > 0)
                {
                    lvNpcs.Items[0].Selected = true;
                }

                UpdateHeaderInfo();
                UpdateUndoButton();
                lblStatus.Text = string.Format("已加载存档 [{0}] ({1}) — 存档内 NPC 共 {2} 名。",
                    entry.SlotName, entry.CharacterName, saveNpcMap.Count);
                var verWarn = CheckSaveVersion();
                if (verWarn != null) lblStatus.Text = verWarn;
            }
            catch (Exception ex)
            {
                lblStatus.Text = "读取存档失败（如果游戏正在写入，请稍后点【刷新】重试）：" + ex.Message;
            }
        }

        private void IndexSaveNpcs()
        {
            saveNpcMap.Clear();
            if (rootNode == null || rootNode.Kind != MsgPackKind.Map) return;

            var npcsNode = rootNode.GetMapValue("npcs") ?? rootNode.GetMapValue("NpcModels");
            if (npcsNode == null) return;

            if (npcsNode.Kind == MsgPackKind.Map && npcsNode.MapEntries != null)
            {
                foreach (var kv in npcsNode.MapEntries)
                    AddNpcNodeIfValid(kv.Value);
            }
            else if (npcsNode.Kind == MsgPackKind.Array && npcsNode.ArrayItems != null)
            {
                foreach (var item in npcsNode.ArrayItems)
                    AddNpcNodeIfValid(item);
            }
        }

        private void AddNpcNodeIfValid(MsgPackNode npcNode)
        {
            if (npcNode == null || npcNode.Kind != MsgPackKind.Map) return;
            var cfgIdNode = npcNode.GetMapValue("npcCfgId") ?? npcNode.GetMapValue("NpcCfgId");
            if (cfgIdNode != null)
            {
                int cfgId = cfgIdNode.AsInt32(-1);
                if (cfgId > 0)
                    saveNpcMap[cfgId] = npcNode;
            }
        }

        // 后台监控：只盯【当前选中的这一个存档文件】。
        // 游戏重新写入它之后，若开启了锁定，就把 NPC 天赋修改重新套上并写回同一个文件。绝不读写其他存档。
        private void OnLiveWatchTimerTick(object sender, EventArgs e)
        {
            if (isWritingDisk || currentSlot == null) return;
            if (!chkAutoLockEdits.Checked || lockedNpcEdits.Count == 0) return;

            try
            {
                if (!File.Exists(currentSlot.GameWorldPath)) return;
                DateTime wt = File.GetLastWriteTimeUtc(currentSlot.GameWorldPath);
                if (wt <= lastKnownDiskWriteUtc.AddSeconds(1.0)) return;

                // 文件可能还在被游戏写入：解密/校验失败会抛异常，留到下一次 Tick 再试
                ReloadCurrentSlotFromDisk();
                ReapplyLockedEditsToRootNode();
                WriteCurrentSaveImmediately(false);

                RefreshDaoTabUI();
                RefreshNpcListView();
                lblStatus.Text = string.Format("{0} 检测到游戏重新写入了存档 [{1}]，已把 {2} 名 NPC 的天赋修改重新写回。",
                    DateTime.Now.ToString("HH:mm:ss"), currentSlot.SlotName, lockedNpcEdits.Count);
            }
            catch
            {
            }
        }

        // 从磁盘重新读取当前选中的存档（只读这一个文件）
        private void ReloadCurrentSlotFromDisk()
        {
            byte[] rawBytes = File.ReadAllBytes(currentSlot.GameWorldPath);
            bool enc;
            byte[] plainBytes = SimpleSaveCrypto.DecryptOrPassThrough(rawBytes, out enc);
            rootNode = MsgPackNode.Parse(plainBytes);
            currentWasEncrypted = enc;
            lastKnownDiskWriteUtc = File.GetLastWriteTimeUtc(currentSlot.GameWorldPath);
            IndexSaveNpcs();
        }

        // 操作前：如果游戏在这期间写过这个存档，先读入最新内容，避免把游戏的新进度冲掉
        private void ReloadIfDiskChanged()
        {
            if (currentSlot == null || !File.Exists(currentSlot.GameWorldPath)) return;
            if (File.GetLastWriteTimeUtc(currentSlot.GameWorldPath) <= lastKnownDiskWriteUtc) return;
            ReloadCurrentSlotFromDisk();
            if (chkAutoLockEdits.Checked)
                ReapplyLockedEditsToRootNode();
        }

        private void ReapplyLockedEditsToRootNode()
        {
            // 只重新套用天赋槽；好感度是游戏里会正常变化的数值，不锁定
            foreach (var kv in lockedNpcEdits)
                ApplyPendingEditToAst(kv.Value, false);
        }

        // =========================================================================
        // 7. 玩家道途点 & 灵根重置逻辑
        // =========================================================================
        private MsgPackNode GetPlayerModelNode()
        {
            if (rootNode == null || rootNode.Kind != MsgPackKind.Map) return null;
            return rootNode.GetMapValue("playerModel") ?? rootNode.GetMapValue("PlayerModel");
        }

        private MsgPackNode GetTalentPathNode()
        {
            var pm = GetPlayerModelNode();
            if (pm == null || pm.Kind != MsgPackKind.Map) return null;
            return pm.GetMapValue("talent_path") ?? pm.GetMapValue("talentPath");
        }

        private void RefreshDaoTabUI()
        {
            RefreshBagListView();
            RefreshAlignmentCharmUI();
            RefreshExploreUI();
            RefreshArtifactList();
            RefreshAttrTab();
            RefreshRepTab();
            RefreshLearnTab();
            RefreshCompanionList();
            RefreshAlchemyTab();
            RefreshDifficultyUI();
            var pm = GetPlayerModelNode();
            var tp = GetTalentPathNode();
            if (pm == null || tp == null || tp.Kind != MsgPackKind.Map)
            {
                lblPlayerSummary.Text = "未在当前存档中找到玩家道途数据 (talent_path)。";
                lstLearnedNodes.Items.Clear();
                return;
            }

            string pName = (pm.GetMapValue("playerName") != null ? pm.GetMapValue("playerName").AsString() : null) ?? currentSlot.CharacterName;
            var ptsNode = tp.GetMapValue("talent_path_points") ?? tp.GetMapValue("PathPoints");
            int currentPts = ptsNode != null ? ptsNode.AsInt32(0) : 0;

            var learnedNode = tp.GetMapValue("talent_path_learned_nodes") ?? tp.GetMapValue("LearnedNodeIds");
            var learnedIds = new List<int>();
            if (learnedNode != null && learnedNode.Kind == MsgPackKind.Array && learnedNode.ArrayItems != null)
            {
                foreach (var item in learnedNode.ArrayItems)
                    learnedIds.Add(item.AsInt32(0));
            }

            int totalSpent = 0;
            lstLearnedNodes.Items.Clear();
            foreach (int nid in learnedIds)
            {
                DaoPathNodeInfo info;
                if (GameDatabase.DaoNodes.TryGetValue(nid, out info))
                {
                    totalSpent += info.Cost;
                    lstLearnedNodes.Items.Add(string.Format("[{0}] {1} (ID:{2}, 消耗:{3}点) — {4}",
                        info.PathName, info.Name, info.Id, info.Cost, info.Desc));
                }
                else
                {
                    lstLearnedNodes.Items.Add(string.Format("道途节点 ID:{0} (未知配置消耗)", nid));
                }
            }

            numPathPoints.Value = Math.Max(0, Math.Min(99999, currentPts));
            lblPlayerSummary.Text = string.Format(
                "角色名：{0}   |   当前剩余道途点：{1} 点\r\n已点亮道途节点：{2} 个（累计已消耗：{3} 点，重置后总可用：{4} 点）",
                pName, currentPts, learnedIds.Count, totalSpent, currentPts + totalSpent);

            var spRemainNode = tp.GetMapValue("spirit_point_remain") ?? tp.GetMapValue("SpiritPointRemain");
            int spRemain = spRemainNode != null ? spRemainNode.AsInt32(0) : 0;
            numSpiritPoints.Value = Math.Max(0, Math.Min(99999, spRemain));

            var spMapNode = tp.GetMapValue("spirit_root_point_map") ?? tp.GetMapValue("SpiritRootPoints");
            int spSpent = 0;
            var spParts = new List<string>();
            string[] elemNames = { "", "金", "木", "水", "火", "土" };
            if (spMapNode != null && spMapNode.Kind == MsgPackKind.Map && spMapNode.MapEntries != null)
            {
                foreach (var kv in spMapNode.MapEntries)
                {
                    int eid = kv.Key.AsInt32(0);
                    int val = kv.Value.AsInt32(0);
                    spSpent += val;
                    string ename = (eid >= 1 && eid <= 5) ? elemNames[eid] : ("元素" + eid);
                    spParts.Add(string.Format("{0}:{1}", ename, val));
                }
            }
            lblSpiritSummary.Text = string.Format(
                "当前已分配灵根点：{0} （合计已投：{1} 点）\r\n当前剩余可用灵根点：{2} 点（重置后总可用：{3} 点）",
                spParts.Count > 0 ? string.Join("  ", spParts) : "无",
                spSpent, spRemain, spRemain + spSpent);
        }

        private Tuple<int, int, int> ExecuteDaoPathResetOnAst()
        {
            var pm = GetPlayerModelNode();
            var tp = GetTalentPathNode();
            if (pm == null || tp == null) return Tuple.Create(0, 0, 0);

            var ptsNode = tp.GetMapValue("talent_path_points");
            int currentPts = ptsNode != null ? ptsNode.AsInt32(0) : 0;

            var learnedNode = tp.GetMapValue("talent_path_learned_nodes");
            int refund = 0;
            int learnedCount = 0;
            if (learnedNode != null && learnedNode.Kind == MsgPackKind.Array && learnedNode.ArrayItems != null)
            {
                learnedCount = learnedNode.ArrayItems.Count;
                foreach (var item in learnedNode.ArrayItems)
                {
                    int nid = item.AsInt32(0);
                    DaoPathNodeInfo info;
                    if (GameDatabase.DaoNodes.TryGetValue(nid, out info))
                        refund += info.Cost;
                }
                learnedNode.ArrayItems.Clear();
                learnedNode.MarkModified();
            }

            var grantedNode = tp.GetMapValue("talent_path_granted_core_passives");
            if (grantedNode != null && grantedNode.Kind == MsgPackKind.Map && grantedNode.MapEntries != null && grantedNode.MapEntries.Count > 0)
            {
                var revokedPassiveIds = new HashSet<long>();
                foreach (var kv in grantedNode.MapEntries)
                    revokedPassiveIds.Add(kv.Value.AsInt64(-1));

                var combatNode = pm.GetMapValue("combat");
                if (combatNode != null && combatNode.Kind == MsgPackKind.Map)
                {
                    var learnedPassives = combatNode.GetMapValue("learned_core_passives");
                    if (learnedPassives != null && learnedPassives.Kind == MsgPackKind.Array && learnedPassives.ArrayItems != null)
                    {
                        learnedPassives.ArrayItems.RemoveAll(x => revokedPassiveIds.Contains(x.AsInt64(-2)));
                        learnedPassives.MarkModified();
                    }
                    // core_passive_slots 实际结构是 Map: { 1: {slot_index, core_passive_id}, 2: {...}, 3: {...} }
                    // 被收回的心法如果正装备着，换成一个仍然已学、且没装备的心法；实在没有才置 0
                    var passiveSlots = combatNode.GetMapValue("core_passive_slots");
                    if (passiveSlots != null && passiveSlots.Kind == MsgPackKind.Map && passiveSlots.MapEntries != null)
                    {
                        var stillLearned = new List<long>();
                        if (learnedPassives != null && learnedPassives.ArrayItems != null)
                            foreach (var x in learnedPassives.ArrayItems) stillLearned.Add(x.AsInt64(-2));

                        var equipped = new HashSet<long>();
                        foreach (var kv in passiveSlots.MapEntries)
                        {
                            var idNode = kv.Value.Kind == MsgPackKind.Map ? kv.Value.GetMapValue("core_passive_id") : null;
                            if (idNode != null) equipped.Add(idNode.AsInt64(-2));
                        }

                        foreach (var kv in passiveSlots.MapEntries)
                        {
                            var idNode = kv.Value.Kind == MsgPackKind.Map ? kv.Value.GetMapValue("core_passive_id") : null;
                            if (idNode == null || !revokedPassiveIds.Contains(idNode.AsInt64(-2))) continue;

                            long replacement = 0;
                            foreach (var cand in stillLearned)
                            {
                                if (cand > 0 && !equipped.Contains(cand)) { replacement = cand; break; }
                            }
                            if (replacement > 0) equipped.Add(replacement);
                            idNode.SetIntValue(replacement);
                        }
                    }
                }

                grantedNode.MapEntries.Clear();
                grantedNode.MarkModified();
            }

            int newTotal = currentPts + refund;
            if (ptsNode != null)
                ptsNode.SetIntValue(newTotal);
            else
                tp.SetMapValue("talent_path_points", MsgPackNode.CreateInt(newTotal));

            return Tuple.Create(learnedCount, refund, newTotal);
        }

        private void ResetPlayerDaoPath()
        {
            if (currentSlot == null) return;
            if (MessageBox.Show(this, "确定要清空全部已学道途节点，并返还消耗的道途点吗？\n（会立即写入选中的存档，写入前自动备份）",
                    "确认重置道途", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            ReloadIfDiskChanged();
            var res = ExecuteDaoPathResetOnAst();
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();

            lblStatus.Text = string.Format("✅ 已重置道途并写入 [{3}]：清空 {0} 个节点，返还 {1} 点，当前可用 {2} 点。",
                res.Item1, res.Item2, res.Item3, currentSlot.SlotName);
        }

        private void ExecuteSetPathPointsOnAst(int val)
        {
            var tp = GetTalentPathNode();
            if (tp == null) return;
            var ptsNode = tp.GetMapValue("talent_path_points");
            if (ptsNode != null)
                ptsNode.SetIntValue(val);
            else
                tp.SetMapValue("talent_path_points", MsgPackNode.CreateInt(val));
        }

        private void UpdatePlayerPathPointsOnly()
        {
            if (currentSlot == null) return;
            int val = (int)numPathPoints.Value;
            ReloadIfDiskChanged();
            ExecuteSetPathPointsOnAst(val);
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已将可用道途点改为 {0} 点并写入 [{1}]。", val, currentSlot.SlotName);
        }

        private Tuple<int, int> ExecuteSpiritResetOnAst()
        {
            var tp = GetTalentPathNode();
            if (tp == null) return Tuple.Create(0, 0);

            var spRemainNode = tp.GetMapValue("spirit_point_remain");
            int spRemain = spRemainNode != null ? spRemainNode.AsInt32(0) : 0;

            var spMapNode = tp.GetMapValue("spirit_root_point_map");
            int refund = 0;
            if (spMapNode != null && spMapNode.Kind == MsgPackKind.Map && spMapNode.MapEntries != null)
            {
                foreach (var kv in spMapNode.MapEntries)
                {
                    refund += kv.Value.AsInt32(0);
                    kv.Value.SetIntValue(0);
                }
                spMapNode.MarkModified();
            }

            int newTotal = spRemain + refund;
            if (spRemainNode != null)
                spRemainNode.SetIntValue(newTotal);
            else
                tp.SetMapValue("spirit_point_remain", MsgPackNode.CreateInt(newTotal));

            return Tuple.Create(refund, newTotal);
        }

        private void ResetPlayerSpiritRoots()
        {
            if (currentSlot == null) return;
            if (MessageBox.Show(this, "确定要清空五系灵根已加的点数，并全部返还吗？\n（会立即写入选中的存档，写入前自动备份）",
                    "确认重置灵根", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            ReloadIfDiskChanged();
            var res = ExecuteSpiritResetOnAst();
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已重置五系灵根并写入 [{2}]：返还 {0} 点，当前可用 {1} 点。", res.Item1, res.Item2, currentSlot.SlotName);
        }

        private void ExecuteSetSpiritPointsOnAst(int val)
        {
            var tp = GetTalentPathNode();
            if (tp == null) return;
            var spRemainNode = tp.GetMapValue("spirit_point_remain");
            if (spRemainNode != null)
                spRemainNode.SetIntValue(val);
            else
                tp.SetMapValue("spirit_point_remain", MsgPackNode.CreateInt(val));
        }

        private void UpdatePlayerSpiritPointsOnly()
        {
            if (currentSlot == null) return;
            int val = (int)numSpiritPoints.Value;
            ReloadIfDiskChanged();
            ExecuteSetSpiritPointsOnAst(val);
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已将剩余灵根点改为 {0} 点并写入 [{1}]。", val, currentSlot.SlotName);
        }

        // =========================================================================
        // 8. NPC 列表与天赋槽位可视化编辑逻辑
        // =========================================================================
        private void RebuildTalentDropdowns()
        {
            int qFilter = cmbFilterQuality.SelectedIndex > 0 ? (6 - cmbFilterQuality.SelectedIndex) : 0;
            string kw = (txtFilterTalent.Text ?? "").Trim();

            filteredTalents = GameDatabase.TalentList.Where(t =>
            {
                if (qFilter > 0 && t.Quality != qFilter) return false;
                if (!string.IsNullOrEmpty(kw))
                {
                    if (t.Name.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0 &&
                        t.Desc.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0 &&
                        t.Id.ToString().IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0)
                        return false;
                }
                return true;
            }).ToList();

            for (int i = 0; i < 4; i++)
            {
                var prev = cmbSlotTalent[i].SelectedItem as TalentInfo;
                int prevId = prev != null ? prev.Id : -1;

                cmbSlotTalent[i].BeginUpdate();
                cmbSlotTalent[i].Items.Clear();

                var listForSlot = new List<TalentInfo>(filteredTalents);
                if (prevId > 0 && !listForSlot.Any(x => x.Id == prevId) && GameDatabase.Talents.ContainsKey(prevId))
                {
                    listForSlot.Insert(0, GameDatabase.Talents[prevId]);
                }

                foreach (var t in listForSlot)
                    cmbSlotTalent[i].Items.Add(t);

                if (prevId > 0)
                {
                    for (int k = 0; k < cmbSlotTalent[i].Items.Count; k++)
                    {
                        if (((TalentInfo)cmbSlotTalent[i].Items[k]).Id == prevId)
                        {
                            cmbSlotTalent[i].SelectedIndex = k;
                            break;
                        }
                    }
                }
                else if (cmbSlotTalent[i].Items.Count > 0)
                {
                    cmbSlotTalent[i].SelectedIndex = 0;
                }
                cmbSlotTalent[i].EndUpdate();
                UpdateSlotDescLabel(i);
            }
        }

        private void UpdateSlotDescLabel(int slotIdx)
        {
            var t = cmbSlotTalent[slotIdx].SelectedItem as TalentInfo;
            if (t == null)
            {
                lblSlotDesc[slotIdx].Text = "未选择天赋";
                return;
            }
            string warn = t.PreviewOnly ? "⚠️ 注意：【敬请期待】为官方未实装占位词条，建议替换为其他正式词条以激活第4槽！" : "";
            lblSlotDesc[slotIdx].Text = string.Format("效果：{0} {1}", t.Desc, warn);
            lblSlotDesc[slotIdx].ForeColor = t.PreviewOnly ? Color.FromArgb(180, 60, 20) : Color.FromArgb(45, 75, 110);
        }

        private void RefreshNpcListView()
        {
            string kw = (txtSearchNpc.Text ?? "").Trim();
            bool onlyComp = chkOnlyCompanion.Checked;
            bool onlyInSave = chkOnlyInSave.Checked;

            lvNpcs.BeginUpdate();
            lvNpcs.Items.Clear();

            foreach (var npc in GameDatabase.NpcList)
            {
                bool inSave = saveNpcMap.ContainsKey(npc.Id);
                if (onlyInSave && !inSave) continue;
                if (onlyComp && !npc.CanBeDaoCompanion) continue;

                string saveTalentsSummary = GetNpcSaveTalentsSummary(npc.Id);
                if (!string.IsNullOrEmpty(kw))
                {
                    bool match = npc.Id.ToString().Contains(kw) ||
                                 npc.Name.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 npc.Title.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 saveTalentsSummary.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 npc.SheetSlotsSummary.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!match) continue;
                }

                int intimacy = GetNpcSaveIntimacy(npc.Id);
                var item = new ListViewItem(npc.Id.ToString());
                item.Tag = npc.Id;
                item.SubItems.Add(npc.Name);
                item.SubItems.Add(string.IsNullOrEmpty(npc.Title) ? "—" : npc.Title);
                item.SubItems.Add(npc.CanBeDaoCompanion ? "是" : "否");
                item.SubItems.Add(inSave ? intimacy.ToString() : "—");
                item.SubItems.Add(saveTalentsSummary);

                if (lockedNpcEdits.ContainsKey(npc.Id))
                    item.BackColor = Color.FromArgb(215, 245, 222);

                lvNpcs.Items.Add(item);
            }

            lvNpcs.EndUpdate();
        }

        private int GetNpcSaveIntimacy(int npcId)
        {
            MsgPackNode npcNode;
            if (!saveNpcMap.TryGetValue(npcId, out npcNode)) return 0;
            var intNode = npcNode.GetMapValue("intimacy") ?? npcNode.GetMapValue("Intimacy");
            return intNode != null ? intNode.AsInt32(0) : 0;
        }

        private string GetNpcSaveTalentsSummary(int npcId)
        {
            MsgPackNode npcNode;
            if (!saveNpcMap.TryGetValue(npcId, out npcNode))
                return "(未在当前存档)";

            var talentNode = npcNode.GetMapValue("talent") ?? npcNode.GetMapValue("Talent");
            if (talentNode == null || talentNode.Kind != MsgPackKind.Map)
                return "(尚未生成天赋槽)";

            var slotsNode = talentNode.GetMapValue("slots") ?? talentNode.GetMapValue("Slots");
            if (slotsNode == null || slotsNode.Kind != MsgPackKind.Array || slotsNode.ArrayItems == null || slotsNode.ArrayItems.Count == 0)
                return "(空槽位)";

            var parts = new List<string>();
            foreach (var s in slotsNode.ArrayItems)
            {
                if (s.Kind != MsgPackKind.Map) continue;
                var sidNode = s.GetMapValue("slot_id") ?? s.GetMapValue("SlotId");
                var tidNode = s.GetMapValue("talent_id") ?? s.GetMapValue("TalentId");
                int sid = sidNode != null ? sidNode.AsInt32(0) : 0;
                int tid = tidNode != null ? tidNode.AsInt32(0) : 0;
                var unlNode = s.GetMapValue("unlocked") ?? s.GetMapValue("IsUnlocked");
                bool unl = unlNode != null && unlNode.AsBool(false);

                TalentInfo tinfo;
                string tname = GameDatabase.Talents.TryGetValue(tid, out tinfo) ? tinfo.Name : tid.ToString();
                parts.Add(string.Format("{0}:{1}{2}", sid, tname, unl ? "✔" : "🔒"));
            }
            return string.Join(" | ", parts);
        }

        private void SelectNpc(int npcId)
        {
            selectedNpcId = npcId;
            NpcConfigInfo cfg;
            if (!GameDatabase.Npcs.TryGetValue(npcId, out cfg)) return;

            bool inSave = saveNpcMap.ContainsKey(npcId);
            lblNpcTitle.Text = string.Format("{0} ({1}) — ID: {2}  [{3}]",
                cfg.Name,
                string.IsNullOrEmpty(cfg.Title) ? "无称号" : cfg.Title,
                cfg.Id,
                cfg.CanBeDaoCompanion ? "可结缘" : "不可结缘");

            txtNpcSheetRef.Text = string.Format(
                "【参考表原始天赋槽】：{0}\r\n【参考表解锁条件】：{1}",
                string.IsNullOrEmpty(cfg.SheetSlotsSummary) ? "见游戏内置配置" : cfg.SheetSlotsSummary,
                string.IsNullOrEmpty(cfg.SheetUnlockCond) ? "无特殊条件" : cfg.SheetUnlockCond);

            numNpcIntimacy.Enabled = inSave;
            numNpcIntimacy.Value = inSave ? Math.Max(-9999, Math.Min(MaxIntimacy, GetNpcSaveIntimacy(npcId))) : 0;

            var currentSlots = new Dictionary<int, Tuple<int, bool>>();
            if (inSave)
            {
                var npcNode = saveNpcMap[npcId];
                var talentNode = npcNode.GetMapValue("talent") ?? npcNode.GetMapValue("Talent");
                if (talentNode != null && talentNode.Kind == MsgPackKind.Map)
                {
                    var slotsNode = talentNode.GetMapValue("slots") ?? talentNode.GetMapValue("Slots");
                    if (slotsNode != null && slotsNode.Kind == MsgPackKind.Array && slotsNode.ArrayItems != null)
                    {
                        foreach (var s in slotsNode.ArrayItems)
                        {
                            if (s.Kind != MsgPackKind.Map) continue;
                            var sidNode = s.GetMapValue("slot_id") ?? s.GetMapValue("SlotId");
                            var tidNode = s.GetMapValue("talent_id") ?? s.GetMapValue("TalentId");
                            int sid = sidNode != null ? sidNode.AsInt32(0) : 0;
                            int tid = tidNode != null ? tidNode.AsInt32(0) : 0;
                            var unlNode = s.GetMapValue("unlocked") ?? s.GetMapValue("IsUnlocked");
                            bool unl = unlNode != null && unlNode.AsBool(false);
                            if (sid >= 1 && sid <= 4 && tid > 0)
                                currentSlots[sid] = Tuple.Create(tid, unl);
                        }
                    }
                }
            }

            PopulateSlotControls(cfg, currentSlots);
            LoadNpcRealmControls(npcId);
        }

        private void PopulateSlotControls(NpcConfigInfo cfg, Dictionary<int, Tuple<int, bool>> currentSlots)
        {
            for (int i = 0; i < 4; i++)
            {
                int slotId = i + 1;
                var cfgSlot = cfg.Slots.FirstOrDefault(x => x.SlotId == slotId);
                Tuple<int, bool> saved;
                bool hasSaved = currentSlots.TryGetValue(slotId, out saved);
                slotFixed[i] = cfgSlot != null && cfgSlot.InitType == 0 && cfgSlot.FixedTalentId > 0;
                slotFixedTalentId[i] = slotFixed[i] ? cfgSlot.FixedTalentId : 0;
                slotFixedInSave[i] = slotFixed[i] && hasSaved;

                if (slotFixed[i])
                {
                    // 固定天赋：永远显示配置里的那个天赋，只能改"是否解锁"
                    // 游戏还没生成这个槽（比如境界不够）就保持不动，不提前塞进去
                    chkSlotEnabled[i].Checked = hasSaved;
                    SelectTalentInCombo(cmbSlotTalent[i], cfgSlot.FixedTalentId);
                    chkSlotUnlocked[i].Checked = hasSaved && saved.Item2;
                }
                else if (hasSaved)
                {
                    chkSlotEnabled[i].Checked = true;
                    SelectTalentInCombo(cmbSlotTalent[i], saved.Item1);
                    chkSlotUnlocked[i].Checked = saved.Item2;
                }
                else if (cfgSlot != null)
                {
                    chkSlotEnabled[i].Checked = true;
                    int defaultTid = cfgSlot.FixedTalentId > 0 ? cfgSlot.FixedTalentId : 106001;
                    SelectTalentInCombo(cmbSlotTalent[i], defaultTid);
                    chkSlotUnlocked[i].Checked = (slotId == 1);
                }
                else
                {
                    chkSlotEnabled[i].Checked = false;
                    chkSlotUnlocked[i].Checked = false;
                }

                cmbSlotTalent[i].Enabled = chkSlotEnabled[i].Checked && !slotFixed[i];
                chkSlotEnabled[i].Enabled = !slotFixed[i];
                chkSlotUnlocked[i].Enabled = chkSlotEnabled[i].Checked;
                var grp = cmbSlotTalent[i].Parent as GroupBox;
                if (grp != null)
                {
                    grp.Text = slotFixed[i] ? string.Format(slotFixedInSave[i] ? "天赋槽 {0}  ■ 固定天赋（游戏设定，不能更换）" : "天赋槽 {0}  ■ 固定天赋（游戏还没生成这个槽，保持不动）", slotId)
                             : (cfgSlot != null && cfgSlot.InitType == 1 ? string.Format("天赋槽 {0}  ◇ 随机天赋（可自由修改）", slotId) : "天赋槽 " + slotId);
                    grp.ForeColor = slotFixed[i] ? Color.FromArgb(150, 90, 20) : SystemColors.ControlText;
                }
                UpdateSlotDescLabel(i);
            }
        }

        private void SelectTalentInCombo(ComboBox cmb, int talentId)
        {
            for (int i = 0; i < cmb.Items.Count; i++)
            {
                if (((TalentInfo)cmb.Items[i]).Id == talentId)
                {
                    cmb.SelectedIndex = i;
                    return;
                }
            }
            TalentInfo t;
            if (!GameDatabase.Talents.TryGetValue(talentId, out t))
            {
                // 存档里有、但内置天赋表里没有的天赋：放一个占位项，保留原 ID，避免沿用上一个 NPC 的选择而写错
                t = new TalentInfo { Id = talentId, Name = "未知天赋", Quality = 1, Category = 0, Desc = "内置表中没有此天赋，保持原样" };
            }
            cmb.Items.Insert(0, t);
            cmb.SelectedIndex = 0;
        }

        private void RestoreSelectedNpcDefaultSlots()
        {
            if (selectedNpcId <= 0) return;
            NpcConfigInfo cfg;
            if (!GameDatabase.Npcs.TryGetValue(selectedNpcId, out cfg)) return;
            PopulateSlotControls(cfg, new Dictionary<int, Tuple<int, bool>>());
        }

        private void ApplyPendingEditToAst(NpcPendingEdit edit, bool applyIntimacy)
        {
            MsgPackNode npcNode;
            if (!saveNpcMap.TryGetValue(edit.NpcId, out npcNode)) return;

            if (applyIntimacy)
            {
                // 好感度上限是 500。max_intimacy 在存档里只会是 0 或 500（像个开关），不能去改它
                int newIntimacy = Math.Min(MaxIntimacy, edit.Intimacy);
                var intNode = npcNode.GetMapValue("intimacy");
                if (intNode == null || intNode.AsInt32(int.MinValue) != newIntimacy)
                {
                    if (intNode != null)
                        intNode.SetIntValue(newIntimacy);
                    else
                        npcNode.SetMapValue("intimacy", MsgPackNode.CreateInt(newIntimacy));
                }
            }

            var talentNode = npcNode.GetMapValue("talent");

            // 记录原有槽位：天赋没换的槽位保留原来的解锁进度 (completed_conditions)
            var oldSlots = new Dictionary<int, MsgPackNode>();
            if (talentNode != null && talentNode.Kind == MsgPackKind.Map)
            {
                var oldSlotsNode = talentNode.GetMapValue("slots");
                if (oldSlotsNode != null && oldSlotsNode.Kind == MsgPackKind.Array && oldSlotsNode.ArrayItems != null)
                {
                    foreach (var os in oldSlotsNode.ArrayItems)
                    {
                        if (os.Kind != MsgPackKind.Map) continue;
                        var sidNode = os.GetMapValue("slot_id");
                        if (sidNode != null) oldSlots[sidNode.AsInt32(0)] = os;
                    }
                }
            }

            var newSlotsList = new List<MsgPackNode>();
            foreach (var s in edit.Slots)
            {
                MsgPackNode keptConditions = null;
                MsgPackNode old;
                if (oldSlots.TryGetValue(s.SlotId, out old))
                {
                    var oldTid = old.GetMapValue("talent_id");
                    var oldCond = old.GetMapValue("completed_conditions");
                    if (oldTid != null && oldTid.AsInt32(0) == s.TalentId && oldCond != null)
                        keptConditions = oldCond;
                }

                var slotMap = MsgPackNode.CreateMap();
                slotMap.SetMapValue("slot_id", MsgPackNode.CreateInt(s.SlotId));
                slotMap.SetMapValue("talent_id", MsgPackNode.CreateInt(s.TalentId));
                slotMap.SetMapValue("unlocked", MsgPackNode.CreateBool(s.Unlocked));
                slotMap.SetMapValue("completed_conditions", keptConditions ?? MsgPackNode.CreateArray());
                newSlotsList.Add(slotMap);
            }

            if (talentNode == null || talentNode.Kind != MsgPackKind.Map)
            {
                talentNode = MsgPackNode.CreateMap();
                npcNode.SetMapValue("talent", talentNode);
            }
            talentNode.SetMapValue("slots", MsgPackNode.CreateArray(newSlotsList));
        }

        private int GetNpcSaveSlotCount(int npcId)
        {
            MsgPackNode npcNode;
            if (!saveNpcMap.TryGetValue(npcId, out npcNode)) return 0;
            var talentNode = npcNode.GetMapValue("talent");
            if (talentNode == null || talentNode.Kind != MsgPackKind.Map) return 0;
            var slotsNode = talentNode.GetMapValue("slots");
            if (slotsNode == null || slotsNode.Kind != MsgPackKind.Array || slotsNode.ArrayItems == null) return 0;
            return slotsNode.ArrayItems.Count;
        }

        private void ApplyCurrentNpcEditsAndWriteDisk(bool writeImmediately)
        {
            if (selectedNpcId <= 0) return;
            if (!saveNpcMap.ContainsKey(selectedNpcId))
            {
                MessageBox.Show(this, "该 NPC 当前不在已加载的存档中，无法直接写入。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var usedTalentIds = new HashSet<int>();
            var pending = new NpcPendingEdit
            {
                NpcId = selectedNpcId,
                Intimacy = (int)numNpcIntimacy.Value
            };

            for (int i = 0; i < 4; i++)
            {
                TalentInfo t;
                if (slotFixed[i])
                {
                    if (!slotFixedInSave[i]) continue;   // 游戏还没生成的固定槽：不写
                    // 固定天赋槽：不管界面上是什么，都写回配置里的固定天赋
                    if (!GameDatabase.Talents.TryGetValue(slotFixedTalentId[i], out t))
                        t = new TalentInfo { Id = slotFixedTalentId[i], Name = "固定天赋", Desc = "" };
                }
                else
                {
                    if (!chkSlotEnabled[i].Checked) continue;
                    t = cmbSlotTalent[i].SelectedItem as TalentInfo;
                    if (t == null) continue;
                }

                if (!usedTalentIds.Add(t.Id))
                {
                    MessageBox.Show(this,
                        string.Format("同一个 NPC 的不同天赋槽不能配置相同的天赋【{0} ({1})】！\n（游戏底层校验 NpcTalentQuery.EvaluateCore 会拒绝同角色重复词条）\n\n请为天赋槽 {2} 选择另一个不同的天赋。", t.Name, t.Id, i + 1),
                        "防冲突校验提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                pending.Slots.Add(new NpcSlotEditItem
                {
                    SlotId = i + 1,
                    TalentId = t.Id,
                    Unlocked = chkSlotUnlocked[i].Checked
                });
            }

            if (GetNpcSaveSlotCount(selectedNpcId) == 0 && pending.Slots.Count > 0)
            {
                if (MessageBox.Show(this,
                        "这个 NPC 在存档里原本没有任何天赋槽（游戏还没给他生成）。\n强行加上后游戏会怎么处理无法保证。\n\n确定还要写入吗？",
                        "提醒", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    return;
            }

            lockedNpcEdits[selectedNpcId] = pending;

            ReloadIfDiskChanged();
            ApplyPendingEditToAst(pending, true);

            if (writeImmediately)
            {
                if (!WriteCurrentSaveImmediately(false)) return;
            }

            foreach (ListViewItem item in lvNpcs.Items)
            {
                if ((int)item.Tag == selectedNpcId)
                {
                    item.SubItems[4].Text = pending.Intimacy.ToString();
                    item.SubItems[5].Text = GetNpcSaveTalentsSummary(selectedNpcId);
                    item.BackColor = Color.FromArgb(215, 245, 222);
                    break;
                }
            }

            NpcConfigInfo cfg = GameDatabase.Npcs[selectedNpcId];
            lblStatus.Text = string.Format("✅ 已把【{0} ({1})】的天赋与好感写入 [{2}]（本次共改了 {3} 名角色）。",
                cfg.Name, selectedNpcId, currentSlot.SlotName, lockedNpcEdits.Count);
        }

        // =========================================================================
        // 8.4 善恶值 & 魅力值
        //   善恶值：playerModel.player_prop_evil（整数，正=善，负=恶，称号阈值见 tbalignmenttitle）
        //   魅力值：属性 ID 6 = base_attrs[6] + growth_attrs[6] + permanent_attrs[6] 里所有加成
        //     permanent_attrs[6] 每条：[来源类型, 来源键, 实例键, 属性ID, 数值(float), 时间ticks, 显示名]
        //     本工具只增删一条显示名为"存档修改器"的加成，不动吃果子等真实加成
        // =========================================================================
        private const int CharmAttrId = 6;
        private const string EditorModifierName = "存档修改器";

        private static string AlignmentTitle(long v)
        {
            if (v <= -2000) return "万夫所指";
            if (v <= -1000) return "臭名昭著";
            if (v < 1000) return "无名之辈";
            if (v < 2000) return "乐善好施";
            return "德高望重";
        }

        private MsgPackNode GetCombatNode()
        {
            var pm = GetPlayerModelNode();
            var c = pm != null ? pm.GetMapValue("combat") : null;
            return (c != null && c.Kind == MsgPackKind.Map) ? c : null;
        }

        private static bool IsEditorModifier(MsgPackNode entry)
        {
            return entry != null && entry.Kind == MsgPackKind.Array && entry.ArrayItems != null && entry.ArrayItems.Count >= 7
                && entry.ArrayItems[6].Kind == MsgPackKind.String && entry.ArrayItems[6].StrVal == EditorModifierName;
        }

        // 返回：基础, 成长, 真实永久加成合计, 本工具加成合计
        private double[] GetCharmBreakdown()
        {
            var r = new double[4];
            var c = GetCombatNode();
            if (c == null) return null;
            var b = c.GetMapValue("base_attrs");
            var g = c.GetMapValue("growth_attrs");
            var bv = b != null ? b.GetMapValueByInt(CharmAttrId) : null;
            var gv = g != null ? g.GetMapValueByInt(CharmAttrId) : null;
            r[0] = bv != null ? bv.AsDouble(0) : 0;
            r[1] = gv != null ? gv.AsDouble(0) : 0;
            var pa = c.GetMapValue("permanent_attrs");
            var list = pa != null ? pa.GetMapValueByInt(CharmAttrId) : null;
            if (list != null && list.Kind == MsgPackKind.Array && list.ArrayItems != null)
            {
                foreach (var e in list.ArrayItems)
                {
                    if (e.Kind != MsgPackKind.Array || e.ArrayItems == null || e.ArrayItems.Count < 5) continue;
                    double v = e.ArrayItems[4].AsDouble(0);
                    if (IsEditorModifier(e)) r[3] += v; else r[2] += v;
                }
            }
            return r;
        }

        private void RefreshAlignmentCharmUI()
        {
            if (numAlignment == null) return;
            long good, evil;
            bool hasAl = GetAlignmentParts(out good, out evil);
            long alv = good + evil;
            numAlignment.Value = Math.Max(numAlignment.Minimum, Math.Min(numAlignment.Maximum, alv));
            lblAlignmentInfo.Text = !hasAl ? "存档里没找到善恶值。" : string.Format(
                "= 善值 {0} + 恶值 {1}　对应称号：{2}\r\n（≤-2000 万夫所指 / ≤-1000 臭名昭著 / ±999 无名之辈 / ≥1000 乐善好施 / ≥2000 德高望重）",
                good, evil, AlignmentTitle(alv));

            RefreshDemonQiUI();

            var cb = GetCharmBreakdown();
            if (cb == null)
            {
                lblCharmInfo.Text = "存档里没找到魅力数据。";
                return;
            }
            double total = cb[0] + cb[1] + cb[2] + cb[3];
            numCharm.Value = (decimal)Math.Max(-99999, Math.Min(99999, Math.Round(total)));
            lblCharmInfo.Text = string.Format("组成：基础 {0} + 成长 {1} + 吃果子等永久加成 {2} + 本工具调整 {3} = {4}\r\n" +
                "注意：道途节点、天赋等加成是游戏实时计算的，不在存档里，游戏里显示的数值会再加上它们。",
                cb[0], cb[1], cb[2], cb[3], total);
        }

        // ---- 五项探索属性 ----
        //   playerModel.interact_attributes = { 1001 灵机, 1002 体魄, 1003 神识, 1004 辩道, 1005 医术 }，值是累计经验
        //   升级经验表来自 tbinteractattribute（五项相同）；各境界有上限：炼气 600 / 筑基 1500 / 结丹 2700 / 元婴 5700
        private static readonly int[] ExploreIds = { 1001, 1002, 1003, 1004, 1005 };
        private static readonly string[] ExploreNames = { "灵机", "体魄", "神识", "辩道", "医术" };
        private static readonly int[] ExploreLevelExp = { 100, 200, 300, 400, 500, 600, 750, 900, 1050, 1200, 1350, 1500, 1700, 1900, 2100, 2300, 2500, 2700, 3100, 3500, 4000, 4500, 5100, 5700 };

        private static int ExploreLevel(long exp)
        {
            int lv = 1;
            foreach (var t in ExploreLevelExp) if (exp >= t) lv++;
            return lv;
        }

        private MsgPackNode GetExploreNode()
        {
            var pm = GetPlayerModelNode();
            var n = pm != null ? pm.GetMapValue("interact_attributes") : null;
            return (n != null && n.Kind == MsgPackKind.Map) ? n : null;
        }

        private bool refreshingExplore = false;

        private void RefreshExploreUI()
        {
            if (numExplore[0] == null) return;
            var n = GetExploreNode();
            refreshingExplore = true;
            for (int i = 0; i < 5; i++)
            {
                var v = n != null ? n.GetMapValueByInt(ExploreIds[i]) : null;
                long exp = v != null ? v.AsInt64(0) : 0;
                numExplore[i].Value = Math.Max(0, Math.Min(numExplore[i].Maximum, exp));
                numExplore[i].Enabled = n != null;
            }
            refreshingExplore = false;
            UpdateExploreInfo();
        }

        private void UpdateExploreInfo()
        {
            if (refreshingExplore || lblExploreInfo == null) return;
            var parts = new List<string>();
            for (int i = 0; i < 5; i++) lblExploreLv[i].Text = "Lv." + ExploreLevel((long)numExplore[i].Value);
            lblExploreInfo.Text = "各境界上限：炼气 600 / 筑基 1500 / 结丹 2700 / 元婴 5700，超出的部分游戏可能要突破后才认。";
        }

        private void SetExploreAndWrite()
        {
            if (currentSlot == null) return;
            var vals = new long[5];
            for (int i = 0; i < 5; i++) vals[i] = (long)numExplore[i].Value;
            ReloadIfDiskChanged();
            var n = GetExploreNode();
            if (n == null)
            {
                MessageBox.Show(this, "存档里没找到探索属性数据。", "错误");
                return;
            }
            for (int i = 0; i < 5; i++)
            {
                var v = n.GetMapValueByInt(ExploreIds[i]);
                if (v != null)
                {
                    if (v.AsInt64(long.MinValue) != vals[i]) v.SetIntValue(vals[i]);
                }
                else
                {
                    var key = MsgPackNode.CreateInt(ExploreIds[i]);
                    var val = MsgPackNode.CreateInt(vals[i]);
                    key.Parent = n; val.Parent = n;
                    n.MapEntries.Add(new KeyValuePair<MsgPackNode, MsgPackNode>(key, val));
                    n.MarkModified();
                }
            }
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已写入五项探索属性（{0}）到 [{1}]。",
                string.Join("，", Enumerable.Range(0, 5).Select(i => ExploreNames[i] + " " + vals[i])), currentSlot.SlotName);
        }

        // ---- 魔气值 ----
        //   playerModel.demonic_cultivator.current_demonic_qi（整数，单位：层）
        //   上限来自魔修道途：901 吞魄入魔 = 初始上限 250；902/903/905/907 各 +25；908/909/911 各 +50
        //   魔气达到上限会走火入魔、进入【堕入魔界】结局，所以最多只允许设到 上限-1
        private static readonly Dictionary<int, int> DemonQiCapNodes = new Dictionary<int, int>
        {
            { 901, 250 }, { 902, 25 }, { 903, 25 }, { 905, 25 }, { 907, 25 }, { 908, 50 }, { 909, 50 }, { 911, 50 }
        };
        private const int DemonQiForcedMax = 249;

        private MsgPackNode GetDemonicNode()
        {
            var pm = GetPlayerModelNode();
            var d = pm != null ? pm.GetMapValue("demonic_cultivator") : null;
            return (d != null && d.Kind == MsgPackKind.Map) ? d : null;
        }

        // 返回魔气上限；没学吞魄入魔返回 0
        private int GetDemonQiCap()
        {
            var tp = GetTalentPathNode();
            var learned = tp != null ? tp.GetMapValue("talent_path_learned_nodes") : null;
            if (learned == null || learned.Kind != MsgPackKind.Array || learned.ArrayItems == null) return 0;
            var ids = new HashSet<int>(learned.ArrayItems.Select(x => x.AsInt32(0)));
            if (!ids.Contains(901)) return 0;
            int cap = 0;
            foreach (var kv in DemonQiCapNodes)
                if (ids.Contains(kv.Key)) cap += kv.Value;
            return cap;
        }

        private void RefreshDemonQiUI()
        {
            if (numDemonQi == null) return;
            var d = GetDemonicNode();
            if (d == null)
            {
                numDemonQi.Enabled = false;
                chkDemonQiForce.Visible = false;
                lblDemonQiInfo.Text = "存档里没找到魔气数据。";
                return;
            }
            var qiNode = d.GetMapValue("current_demonic_qi");
            long qi = qiNode != null ? qiNode.AsInt64(0) : 0;
            var pendNode = d.GetMapValue("demon_realm_transition_pending");
            bool pending = pendNode != null && pendNode.AsBool(false);
            int cap = GetDemonQiCap();

            int maxAllowed;
            string info;
            if (cap > 0)
            {
                maxAllowed = cap - 1;
                chkDemonQiForce.Visible = false;
                info = string.Format("当前 {0} 层，上限 {1} 层（由已学魔修道途算出）。最多可设 {2} 层，达到上限会走火入魔、进入【堕入魔界】结局。", qi, cap, maxAllowed);
            }
            else
            {
                chkDemonQiForce.Visible = true;
                maxAllowed = chkDemonQiForce.Checked ? DemonQiForcedMax : 0;
                info = string.Format("当前 {0} 层。你还没学魔修道途【吞魄入魔】，魔气系统没有开启，上限不确定，随便改可能直接触发【堕入魔界】结局。", qi);
            }
            if (pending) info += "\r\n⚠ 存档里标记了\"即将堕入魔界\"。";

            numDemonQi.Enabled = maxAllowed > 0 || qi > 0;
            numDemonQi.Maximum = Math.Max(maxAllowed, (int)Math.Min(qi, int.MaxValue));
            numDemonQi.Value = Math.Max(0, Math.Min(numDemonQi.Maximum, qi));
            lblDemonQiInfo.Text = info;
        }

        private void SetDemonQiAndWrite()
        {
            if (currentSlot == null) return;
            long v = (long)numDemonQi.Value;
            ReloadIfDiskChanged();
            var d = GetDemonicNode();
            if (d == null)
            {
                MessageBox.Show(this, "存档里没找到魔气数据。", "错误");
                return;
            }
            int cap = GetDemonQiCap();
            long maxAllowed = cap > 0 ? cap - 1 : (chkDemonQiForce.Checked ? DemonQiForcedMax : 0);
            if (v > maxAllowed)
            {
                MessageBox.Show(this, string.Format("魔气最多只能设到 {0} 层，再高会走火入魔、进入【堕入魔界】结局。", maxAllowed), "超出上限");
                RefreshDemonQiUI();
                return;
            }
            if (cap == 0 && v > 0 && MessageBox.Show(this,
                    "你还没学魔修道途【吞魄入魔】，游戏的魔气上限不确定。\n修改后有可能一进游戏就走火入魔、进入【堕入魔界】结局。\n\n写入前会自动备份，出问题可以用【还原备份】恢复。\n确定要写入吗？",
                    "风险提醒", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;

            var qiNode = d.GetMapValue("current_demonic_qi");
            if (qiNode != null) qiNode.SetIntValue(v);
            else d.SetMapValue("current_demonic_qi", MsgPackNode.CreateInt(v));

            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已把魔气值改为 {0} 层，并写入 [{1}]。", v, currentSlot.SlotName);
        }

        // 善恶值 = behavior_value.player_good（善值，≥0）+ behavior_value.player_evil（恶值，≤0）
        // 游戏配置里善恶变化就是分成 playerGoodDelta / playerEvilDelta(负数) 两部分记的
        // （早期开发版误改的是 player_prop_evil，那个字段所有存档都是固定 800，不是善恶值）
        private const long PlayerPropEvilDefault = 800;

        private MsgPackNode GetBehaviorValueNode()
        {
            var pm = GetPlayerModelNode();
            var bv = pm != null ? pm.GetMapValue("behavior_value") : null;
            return (bv != null && bv.Kind == MsgPackKind.Map) ? bv : null;
        }

        private bool GetAlignmentParts(out long good, out long evil)
        {
            good = 0; evil = 0;
            var bv = GetBehaviorValueNode();
            if (bv == null) return false;
            var g = bv.GetMapValue("player_good");
            var e = bv.GetMapValue("player_evil");
            if (g == null && e == null) return false;
            good = g != null ? g.AsInt64(0) : 0;
            evil = e != null ? e.AsInt64(0) : 0;
            return true;
        }

        private void SetAlignmentAndWrite()
        {
            if (currentSlot == null) return;
            long target = (long)numAlignment.Value;
            ReloadIfDiskChanged();
            var bv = GetBehaviorValueNode();
            if (bv == null)
            {
                MessageBox.Show(this, "存档里没找到善恶值数据。", "错误");
                return;
            }
            long good, evil;
            GetAlignmentParts(out good, out evil);

            // 尽量保留原来的恶值，只调善值；目标比现有恶值还低时，善值清零、恶值=目标
            long newGood, newEvil;
            if (target - evil >= 0) { newGood = target - evil; newEvil = evil; }
            else { newGood = 0; newEvil = target; }

            var gNode = bv.GetMapValue("player_good");
            if (gNode != null) gNode.SetIntValue(newGood); else bv.SetMapValue("player_good", MsgPackNode.CreateInt(newGood));
            var eNode = bv.GetMapValue("player_evil");
            if (eNode != null) eNode.SetIntValue(newEvil); else bv.SetMapValue("player_evil", MsgPackNode.CreateInt(newEvil));

            // 顺手把旧版本误改的 player_prop_evil 恢复成原值 800
            var pm = GetPlayerModelNode();
            var wrong = pm != null ? pm.GetMapValue("player_prop_evil") : null;
            bool restored = false;
            if (wrong != null && wrong.AsInt64(PlayerPropEvilDefault) != PlayerPropEvilDefault)
            {
                wrong.SetIntValue(PlayerPropEvilDefault);
                restored = true;
            }

            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已把善恶值改为 {0}（善值 {1} + 恶值 {2}，{3}）{4}，并写入 [{5}]。",
                target, newGood, newEvil, AlignmentTitle(target), restored ? "，并修复了旧版误改的字段" : "", currentSlot.SlotName);
        }

        private void SetCharmAndWrite()
        {
            if (currentSlot == null) return;
            double desired = (double)numCharm.Value;
            ReloadIfDiskChanged();
            var c = GetCombatNode();
            var cb = GetCharmBreakdown();
            if (c == null || cb == null)
            {
                MessageBox.Show(this, "存档里没找到魅力数据。", "错误");
                return;
            }
            double needed = desired - (cb[0] + cb[1] + cb[2]);   // 本工具那一条需要的数值

            var pa = c.GetMapValue("permanent_attrs");
            if (pa == null || pa.Kind != MsgPackKind.Map)
            {
                MessageBox.Show(this, "存档里没找到永久属性加成数据，无法修改魅力。", "错误");
                return;
            }
            var list = pa.GetMapValueByInt(CharmAttrId);
            if (list == null || list.Kind != MsgPackKind.Array)
            {
                list = MsgPackNode.CreateArray();
                var key = MsgPackNode.CreateInt(CharmAttrId);
                key.Parent = pa;
                list.Parent = pa;
                pa.MapEntries.Add(new KeyValuePair<MsgPackNode, MsgPackNode>(key, list));
                pa.MarkModified();
            }

            // 去掉旧的本工具加成，再按需要加一条新的
            list.ArrayItems.RemoveAll(IsEditorModifier);
            if (Math.Abs(needed) > 0.0001)
            {
                var entry = MsgPackNode.CreateArray(new List<MsgPackNode>
                {
                    MsgPackNode.CreateInt(5),                                          // 来源类型：物品（和吃果子相同）
                    MsgPackNode.CreateString("item:220004"),                           // 来源键：用真实存在的魅力果(石衣果)ID，避免游戏查不到来源
                    MsgPackNode.CreateString("item:0:" + Guid.NewGuid().ToString("N")),// 实例键（唯一）
                    MsgPackNode.CreateInt(CharmAttrId),                                // 属性 ID：魅力
                    MsgPackNode.CreateFloat((float)needed),                            // 数值
                    MsgPackNode.CreateInt(DateTime.Now.Ticks),                         // 时间
                    MsgPackNode.CreateString(EditorModifierName)                       // 显示名
                });
                entry.Parent = list;
                list.ArrayItems.Add(entry);
            }
            list.MarkModified();

            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已把存档内魅力合计改为 {0}（本工具加成 {1:+0;-0;0}），并写入 [{2}]。", desired, needed, currentSlot.SlotName);
        }

        // =========================================================================
        // 8.5 背包物品：查看 / 修改数量 / 添加新物品
        //   存档里 bag.items 每一格是 [格式编号, {字段}]：
        //   0=普通物品  2=法宝(带词条)  3=丹药(带药效)  4=璞石  5=功法/心法
        //   只允许"添加"普通物品；丹药和普通物品可以改数量
        // =========================================================================
        private const int MaxNewStacksPerAdd = 200;
        private const int MaxIntimacy = 500;   // 游戏里满好感是 500（存档里所有 NPC 好感都不超过 500）

        private void BuildBagTab(TabPage tab)
        {
            // 用 Dock 布局：创建时面板尺寸还是默认的小尺寸，用绝对坐标会错位
            var split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
            Shown += (s, e) => { try { split.SplitterDistance = 540; } catch { } };
            tab.Enter += (s, e) => { try { if (split.SplitterDistance < 400) split.SplitterDistance = 540; } catch { } };

            // ---- 左侧：当前背包 ----
            var pnlLeft = split.Panel1;
            pnlLeft.Padding = new Padding(8);
            var pnlLeftTop = new Panel { Dock = DockStyle.Top, Height = 30 };
            lblBagSummary = new Label { Text = "当前背包：未加载存档", Location = new Point(2, 6), AutoSize = true, Font = new Font(Font, FontStyle.Bold) };
            pnlLeftTop.Controls.Add(lblBagSummary);

            lvBag = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                MultiSelect = false
            };
            lvBag.Columns.Add("名称", 130);
            lvBag.Columns.Add("ID", 64);
            lvBag.Columns.Add("类型", 90);
            lvBag.Columns.Add("数量", 80);
            lvBag.Columns.Add("每格上限", 80);
            lvBag.Columns.Add("格式", 70);
            lvBag.SelectedIndexChanged += (s, e) =>
            {
                if (lvBag.SelectedItems.Count == 0) return;
                var tag = (long[])lvBag.SelectedItems[0].Tag;
                numBagCount.Maximum = Math.Max(1, tag[2]);
                numBagCount.Value = Math.Max(1, Math.Min(tag[2], tag[1]));
            };

            var pnlLeftBottom = new Panel { Dock = DockStyle.Bottom, Height = 84 };
            var lblCnt = new Label { Text = "选中这一格的新数量：", Location = new Point(2, 16), AutoSize = true };
            numBagCount = new NumericUpDown { Minimum = 1, Maximum = 999999999, Value = 1, Width = 130, ThousandsSeparator = true, Location = new Point(150, 12) };
            var btnSetCount = new Button
            {
                Text = "修改数量并写入存档",
                Size = new Size(180, 30),
                Location = new Point(290, 9),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnSetCount.Click += (s, e) => SetSelectedBagStackCount();
            var btnDelete = new Button { Text = "🗑 删除选中的这一格", Location = new Point(290, 46), Size = new Size(180, 30) };
            btnDelete.Click += (s, e) => DeleteSelectedBagStack();
            pnlLeftBottom.Controls.AddRange(new Control[] { lblCnt, numBagCount, btnSetCount, btnDelete });

            // 先加 Fill，再加 Top/Bottom（WinForms 按反序停靠）
            pnlLeft.Controls.Add(lvBag);
            pnlLeft.Controls.Add(pnlLeftBottom);
            pnlLeft.Controls.Add(pnlLeftTop);

            // ---- 右侧：添加物品 ----
            var pnlRight = split.Panel2;
            pnlRight.Padding = new Padding(8);
            var pnlRightTop = new Panel { Dock = DockStyle.Top, Height = 66 };
            var lblAddTitle = new Label { Text = "添加物品到背包", Location = new Point(2, 4), AutoSize = true, Font = new Font(Font.FontFamily, 11f, FontStyle.Bold), ForeColor = Color.FromArgb(25, 65, 120) };

            var lblSearch = new Label { Text = "搜索名称/ID：", Location = new Point(2, 38), AutoSize = true };
            txtSearchItem = new TextBox { Location = new Point(95, 34), Width = 170 };
            txtSearchItem.TextChanged += (s, e) => RefreshAddItemList();

            var lblBagPage = new Label { Text = "分类：", Location = new Point(280, 38), AutoSize = true };
            cmbItemBag = new ComboBox { Location = new Point(325, 34), Width = 150, DropDownStyle = ComboBoxStyle.DropDownList };
            cmbItemBag.Items.Add("全部");
            foreach (var tn in GameDatabase.ItemList.Where(x => x.Addable > 0).Select(x => x.TypeName).Distinct().OrderBy(x => x))
                cmbItemBag.Items.Add(tn);
            cmbItemBag.SelectedIndex = 0;
            cmbItemBag.SelectedIndexChanged += (s, e) => RefreshAddItemList();

            chkShowUnverified = new CheckBox { Text = "显示未验证的物品", Location = new Point(490, 36), AutoSize = true };
            chkShowUnverified.CheckedChanged += (s, e) => RefreshAddItemList();
            pnlRightTop.Controls.AddRange(new Control[] { lblAddTitle, lblSearch, txtSearchItem, lblBagPage, cmbItemBag, chkShowUnverified });

            lvAddItems = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                MultiSelect = false
            };
            lvAddItems.Columns.Add("名称", 140);
            lvAddItems.Columns.Add("ID", 70);
            lvAddItems.Columns.Add("类型", 100);
            lvAddItems.Columns.Add("品质", 50);
            lvAddItems.Columns.Add("每格上限", 85);
            lvAddItems.Columns.Add("状态", 70);
            lvAddItems.SelectedIndexChanged += (s, e) =>
            {
                var it = GetSelectedAddItem();
                string extra = "";
                if (it != null)
                {
                    if (it.Addable == 2) extra = "\r\n⚠ 未验证：这一类物品在你的存档里没出现过，添加后游戏能否正常识别无法保证。";
                    else if (it.Addable == 3) extra = "\r\n任务物品：凭空加出来可能让相关任务提前满足条件或出现异常。";
                    else if (it.Format == 2) extra = "\r\n会以【未炼制】的法宝加入，没有词条。";
                    else if (it.Format == 4) extra = "\r\n会以【未鉴定】的璞石加入。";
                    else if (it.Format == 5) extra = "\r\n功法/心法书，加入后在背包里使用即可学习。";
                }
                lblItemDesc.Text = it == null ? "" : string.Format("{0}：{1}{2}", it.Name, it.Desc, extra);
                cmbPillGrade.Visible = lblPillGrade.Visible = it != null && it.Format == 3;
            };

            var pnlRightBottom = new Panel { Dock = DockStyle.Bottom, Height = 158 };
            lblItemDesc = new Label
            {
                Location = new Point(2, 6),
                Size = new Size(640, 50),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                ForeColor = Color.FromArgb(45, 75, 110)
            };

            var lblAddCnt = new Label { Text = "添加数量：", AutoSize = true, Location = new Point(2, 70) };
            numAddCount = new NumericUpDown { Minimum = 1, Maximum = 999999999, Value = 1, Width = 130, ThousandsSeparator = true, Location = new Point(80, 66) };

            var btnAdd = new Button
            {
                Text = "添加到背包并写入存档",
                Size = new Size(200, 32),
                Location = new Point(222, 62),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font(Font, FontStyle.Bold)
            };
            btnAdd.Click += (s, e) =>
            {
                var it = GetSelectedAddItem();
                if (it == null) { MessageBox.Show(this, "请先在列表里选一个物品。", "提示"); return; }
                AddItemAndWrite(it, (long)numAddCount.Value);
            };

            var btnStone1 = new Button { Text = "灵石 +10万", Size = new Size(100, 32), Location = new Point(432, 62) };
            btnStone1.Click += (s, e) => AddItemAndWrite(GameDatabase.Items[50000], 100000);
            var btnStone2 = new Button { Text = "灵石 +100万", Size = new Size(100, 32), Location = new Point(538, 62) };
            btnStone2.Click += (s, e) => AddItemAndWrite(GameDatabase.Items[50000], 1000000);

            var lblNote = new Label
            {
                Text = "说明：法宝、丹药、功法/心法、璞石、任务物品带有额外数据，不能凭空添加（丹药可以在左边改数量）。",
                AutoSize = true,
                Location = new Point(2, 134),
                ForeColor = Color.FromArgb(120, 90, 40)
            };
            lblPillGrade = new Label { Text = "丹药品级：", AutoSize = true, Location = new Point(2, 106), Visible = false };
            cmbPillGrade = new ComboBox { Location = new Point(80, 102), Width = 80, DropDownStyle = ComboBoxStyle.DropDownList, Visible = false };
            cmbPillGrade.Items.AddRange(new object[] { "凡品", "仙品", "神品" });
            cmbPillGrade.SelectedIndex = 0;
            lblNote.Text = "说明：已炼制的法宝（带词条）、本命法宝、虚拟物品、机关道具，以及没有学习效果的功法/没有丹方的丹药不能添加。";
            pnlRightBottom.Controls.AddRange(new Control[] { lblItemDesc, lblAddCnt, numAddCount, btnAdd, btnStone1, btnStone2, lblPillGrade, cmbPillGrade, lblNote });

            pnlRight.Controls.Add(lvAddItems);
            pnlRight.Controls.Add(pnlRightBottom);
            pnlRight.Controls.Add(pnlRightTop);

            tab.Controls.Add(split);
            RefreshAddItemList();
        }

        private ItemInfo GetSelectedAddItem()
        {
            if (lvAddItems.SelectedItems.Count == 0) return null;
            ItemInfo it;
            return GameDatabase.Items.TryGetValue((int)lvAddItems.SelectedItems[0].Tag, out it) ? it : null;
        }

        private void RefreshAddItemList()
        {
            if (lvAddItems == null) return;
            string kw = (txtSearchItem.Text ?? "").Trim();
            string cat = cmbItemBag.SelectedIndex > 0 ? (string)cmbItemBag.SelectedItem : null;
            bool showUnverified = chkShowUnverified.Checked;

            lvAddItems.BeginUpdate();
            lvAddItems.Items.Clear();
            foreach (var it in GameDatabase.ItemList)
            {
                if (it.Addable == 0) continue;
                if (it.Addable == 2 && !showUnverified) continue;
                if (cat != null && it.TypeName != cat) continue;
                if (kw.Length > 0 && it.Name.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0 && !it.Id.ToString().Contains(kw)) continue;

                var lvi = new ListViewItem(it.Name) { Tag = it.Id };
                lvi.SubItems.Add(it.Id.ToString());
                lvi.SubItems.Add(it.TypeName);
                lvi.SubItems.Add(it.QualityText);
                lvi.SubItems.Add(it.MaxPerGrid >= 999999999 ? "无上限" : it.MaxPerGrid.ToString());
                lvi.SubItems.Add(it.StatusText);
                if (it.Addable == 2) lvi.ForeColor = Color.FromArgb(170, 90, 20);
                else if (it.Addable == 3) lvi.ForeColor = Color.FromArgb(120, 70, 150);
                lvAddItems.Items.Add(lvi);
            }
            lvAddItems.EndUpdate();
        }

        private MsgPackNode GetBagNode()
        {
            var pm = GetPlayerModelNode();
            if (pm == null || pm.Kind != MsgPackKind.Map) return null;
            var bag = pm.GetMapValue("bag");
            return (bag != null && bag.Kind == MsgPackKind.Map) ? bag : null;
        }

        private MsgPackNode GetBagItemsNode()
        {
            var bag = GetBagNode();
            if (bag == null) return null;
            var items = bag.GetMapValue("items");
            return (items != null && items.Kind == MsgPackKind.Array && items.ArrayItems != null) ? items : null;
        }

        private static string FormatKindText(long k)
        {
            switch (k)
            {
                case 0: return "普通";
                case 2: return "法宝";
                case 3: return "丹药";
                case 4: return "璞石";
                case 5: return "功法";
                default: return "其他" + k;
            }
        }

        private void RefreshBagListView()
        {
            if (lvBag == null) return;
            lvBag.BeginUpdate();
            lvBag.Items.Clear();
            var items = GetBagItemsNode();
            int stacks = 0;
            long stones = 0;
            if (items != null)
            {
                foreach (var cell in items.ArrayItems)
                {
                    if (cell.Kind != MsgPackKind.Array || cell.ArrayItems == null || cell.ArrayItems.Count < 2) continue;
                    var m = cell.ArrayItems[1];
                    if (m.Kind != MsgPackKind.Map) continue;
                    long kind = cell.ArrayItems[0].AsInt64(-1);
                    int iid = m.GetMapValue("item_id") != null ? m.GetMapValue("item_id").AsInt32(0) : 0;
                    long cnt = m.GetMapValue("count") != null ? m.GetMapValue("count").AsInt64(0) : 0;
                    long uid = m.GetMapValue("uid") != null ? m.GetMapValue("uid").AsInt64(-1) : -1;
                    ItemInfo info;
                    GameDatabase.Items.TryGetValue(iid, out info);
                    long maxPer = info != null ? info.MaxPerGrid : 999;
                    if (iid == 50000) stones += cnt;

                    var lvi = new ListViewItem(info != null ? info.Name : ("未知物品")) { Tag = new long[] { uid, cnt, maxPer, kind } };
                    lvi.SubItems.Add(iid.ToString());
                    lvi.SubItems.Add(info != null ? info.TypeName : "?");
                    lvi.SubItems.Add(cnt.ToString("N0"));
                    lvi.SubItems.Add(maxPer >= 999999999 ? "无上限" : maxPer.ToString());
                    lvi.SubItems.Add(FormatKindText(kind));
                    if (kind != 0 && kind != 3) lvi.ForeColor = Color.Gray;
                    lvBag.Items.Add(lvi);
                    stacks++;
                }
            }
            lvBag.EndUpdate();
            lblBagSummary.Text = items == null ? "当前背包：未找到背包数据" : string.Format("当前背包：{0} 格物品    灵石：{1:N0}", stacks, stones);
        }

        private MsgPackNode FindBagStackByUid(long uid)
        {
            var items = GetBagItemsNode();
            if (items == null) return null;
            foreach (var cell in items.ArrayItems)
            {
                if (cell.Kind != MsgPackKind.Array || cell.ArrayItems == null || cell.ArrayItems.Count < 2) continue;
                var m = cell.ArrayItems[1];
                var u = m.Kind == MsgPackKind.Map ? m.GetMapValue("uid") : null;
                if (u != null && u.AsInt64(-1) == uid) return cell;
            }
            return null;
        }

        private void SetSelectedBagStackCount()
        {
            if (currentSlot == null || lvBag.SelectedItems.Count == 0)
            {
                MessageBox.Show(this, "请先在左边背包列表里选一格物品。", "提示");
                return;
            }
            var tag = (long[])lvBag.SelectedItems[0].Tag;
            long uid = tag[0], kind = tag[3];
            if (kind != 0 && kind != 3)
            {
                MessageBox.Show(this, "法宝、功法、璞石这类物品每一件都是独立的，不能改数量。", "提示");
                return;
            }
            long newCount = (long)numBagCount.Value;

            ReloadIfDiskChanged();
            var cell = FindBagStackByUid(uid);
            if (cell == null)
            {
                MessageBox.Show(this, "在最新的存档里找不到这一格物品了（可能游戏刚改过背包）。请刷新后再试。", "提示");
                RefreshBagListView();
                return;
            }
            var m = cell.ArrayItems[1];
            var cntNode = m.GetMapValue("count");
            if (cntNode != null) cntNode.SetIntValue(newCount);
            else m.SetMapValue("count", MsgPackNode.CreateInt(newCount));

            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshBagListView();
            lblStatus.Text = string.Format("✅ 已把这一格的数量改为 {0:N0}，并写入 [{1}]。", newCount, currentSlot.SlotName);
        }

        // 各种存档格式的专属字段（顺序与游戏存档一致，已用真实样本核对）
        private static void AddFormatSpecificFields(MsgPackNode m, ItemInfo info, int pillGrade)
        {
            var p = info.Params ?? "";
            switch (info.Format)
            {
                case 2: // 法宝（未炼制）
                    m.SetMapValue("skill_type", MsgPackNode.CreateInt(0));
                    m.SetMapValue("skill_id", MsgPackNode.CreateInt(0));
                    m.SetMapValue("effects", MsgPackNode.CreateArray());
                    m.SetMapValue("alchemy_crafted", MsgPackNode.CreateBool(false));
                    m.SetMapValue("alchemy_proto_item_id", MsgPackNode.CreateInt(0));
                    m.SetMapValue("alchemy_tier_id", MsgPackNode.CreateInt(0));
                    m.SetMapValue("alchemy_score", MsgPackNode.CreateInt(0));
                    m.SetMapValue("alchemy_attrs", MsgPackNode.CreateArray());
                    m.SetMapValue("alchemy_affixes", MsgPackNode.CreateArray());
                    m.SetMapValue("pending_alchemy_affixes", MsgPackNode.CreateArray());
                    break;
                case 3: // 丹药："配方ID|scope|g1效果|g1时长|g2效果|g2时长|g3效果|g3时长"
                    {
                        var f = p.Split('|');
                        int g = Math.Max(1, Math.Min(3, pillGrade));
                        string effects = f.Length > 2 * g ? f[2 * g] : "";
                        long duration = f.Length > 2 * g + 1 ? long.Parse(f[2 * g + 1]) : 0;
                        var effList = new List<MsgPackNode>();
                        foreach (var e in effects.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            var kv = e.Split(':');
                            var vals = new List<MsgPackNode>();
                            if (kv.Length > 1)
                                foreach (var v in kv[1].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                                    vals.Add(MsgPackNode.CreateInt(long.Parse(v)));
                            effList.Add(MsgPackNode.CreateArray(new List<MsgPackNode> { MsgPackNode.CreateInt(long.Parse(kv[0])), MsgPackNode.CreateArray(vals) }));
                        }
                        m.SetMapValue("recipe_id", MsgPackNode.CreateInt(long.Parse(f[0])));
                        m.SetMapValue("grade", MsgPackNode.CreateInt(g));
                        m.SetMapValue("scope", MsgPackNode.CreateInt(long.Parse(f[1])));
                        m.SetMapValue("main_effects", MsgPackNode.CreateArray(effList));
                        m.SetMapValue("main_duration", MsgPackNode.CreateInt(duration));
                        m.SetMapValue("sub_effects", MsgPackNode.CreateArray());
                        m.SetMapValue("toxin_value", MsgPackNode.CreateInt(0));
                        m.SetMapValue("herb_composition", MsgPackNode.CreateArray());
                        break;
                    }
                case 4: // 璞石（未鉴定）
                    m.SetMapValue("stone_instance_id", MsgPackNode.CreateInt(0));
                    break;
                case 5: // 功法/心法书："类型,目标ID,等级,阶"
                    {
                        var f = p.Split(',');
                        m.SetMapValue("learn_target_type", MsgPackNode.CreateInt(long.Parse(f[0])));
                        m.SetMapValue("learn_target_id", MsgPackNode.CreateInt(long.Parse(f[1])));
                        m.SetMapValue("learn_target_level", MsgPackNode.CreateInt(long.Parse(f[2])));
                        m.SetMapValue("learn_target_skill_tier", MsgPackNode.CreateInt(long.Parse(f[3])));
                        m.SetMapValue("comprehend_value", MsgPackNode.CreateInt(0));
                        break;
                    }
            }
        }

        // 按游戏的堆叠规则添加：先补满已有的同种物品格子，再开新格子，每格不超过上限
        private void AddItemAndWrite(ItemInfo info, long amount)
        {
            if (currentSlot == null || info == null || amount <= 0) return;
            if (info.Addable == 0)
            {
                MessageBox.Show(this, "这种物品带有额外数据，不能凭空添加。", "提示");
                return;
            }
            if (info.Addable == 2 && MessageBox.Show(this,
                    string.Format("【{0}】这一类物品在你的存档里从没出现过，无法确认游戏用什么格式保存它。\n添加后可能显示异常或无法使用（写入前会自动备份，可以还原）。\n\n确定要添加吗？", info.Name),
                    "未验证的物品", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;
            if (info.Addable == 3 && MessageBox.Show(this,
                    string.Format("【{0}】是任务物品。凭空加出来，相关任务可能提前满足条件、跳过剧情或出现异常。\n（写入前会自动备份，可以还原）\n\n确定要添加吗？", info.Name),
                    "任务物品", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;
            int pillGrade = cmbPillGrade != null && cmbPillGrade.SelectedIndex >= 0 ? cmbPillGrade.SelectedIndex + 1 : 1;

            long newStacksNeeded = 0;
            ReloadIfDiskChanged();
            var bag = GetBagNode();
            var items = GetBagItemsNode();
            if (bag == null || items == null)
            {
                MessageBox.Show(this, "存档里没找到背包数据。", "错误");
                return;
            }

            long remaining = amount;
            // 法宝/璞石/功法书在游戏里每件都是独立一格（数量 1）
            bool oneEach = info.Format == 2 || info.Format == 4 || info.Format == 5;
            long max = oneEach ? 1 : info.MaxPerGrid;

            // 1) 补满已有格子（只补普通格式的同种物品）
            foreach (var cell in items.ArrayItems)
            {
                if (remaining <= 0) break;
                if (cell.Kind != MsgPackKind.Array || cell.ArrayItems == null || cell.ArrayItems.Count < 2) continue;
                if (cell.ArrayItems[0].AsInt64(-1) != 0) continue;
                var m = cell.ArrayItems[1];
                if (m.Kind != MsgPackKind.Map) continue;
                var idNode = m.GetMapValue("item_id");
                var cntNode = m.GetMapValue("count");
                if (idNode == null || cntNode == null || idNode.AsInt32(0) != info.Id) continue;
                long cur = cntNode.AsInt64(0);
                if (cur >= max) continue;
                long add = Math.Min(max - cur, remaining);
                cntNode.SetIntValue(cur + add);
                remaining -= add;
            }

            // 2) 开新格子
            if (remaining > 0)
            {
                newStacksNeeded = (remaining + max - 1) / max;
                if (newStacksNeeded > MaxNewStacksPerAdd)
                {
                    MessageBox.Show(this, string.Format("这个物品每格最多 {0} 个，要添加这么多需要新开 {1} 格，太多了。\n一次最多新开 {2} 格，请减少数量。",
                        max, newStacksNeeded, MaxNewStacksPerAdd), "数量太多");
                    ReloadCurrentSlotFromDisk();
                    RefreshBagListView();
                    return;
                }

                var nextUidNode = bag.GetMapValue("next_uid");
                long nextUid = nextUidNode != null ? nextUidNode.AsInt64(0) : 0;
                // 保险：next_uid 至少要比现有最大 uid 大
                foreach (var cell in items.ArrayItems)
                {
                    if (cell.Kind != MsgPackKind.Array || cell.ArrayItems == null || cell.ArrayItems.Count < 2) continue;
                    var u = cell.ArrayItems[1].Kind == MsgPackKind.Map ? cell.ArrayItems[1].GetMapValue("uid") : null;
                    if (u != null && u.AsInt64(0) >= nextUid) nextUid = u.AsInt64(0) + 1;
                }

                long nowMs = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
                while (remaining > 0)
                {
                    long c = Math.Min(max, remaining);
                    var m = MsgPackNode.CreateMap();
                    AddFormatSpecificFields(m, info, pillGrade);
                    m.SetMapValue("item_id", MsgPackNode.CreateInt(info.Id));
                    m.SetMapValue("count", MsgPackNode.CreateInt(c));
                    m.SetMapValue("is_new", MsgPackNode.CreateBool(true));
                    m.SetMapValue("is_equipped", MsgPackNode.CreateBool(false));
                    m.SetMapValue("timestamp_get", MsgPackNode.CreateInt(nowMs));
                    m.SetMapValue("uid", MsgPackNode.CreateInt(nextUid));
                    var cell = MsgPackNode.CreateArray(new List<MsgPackNode> { MsgPackNode.CreateInt(info.Format), m });
                    cell.Parent = items;
                    items.ArrayItems.Add(cell);
                    nextUid++;
                    remaining -= c;
                }
                items.MarkModified();

                if (nextUidNode != null) nextUidNode.SetIntValue(nextUid);
                else bag.SetMapValue("next_uid", MsgPackNode.CreateInt(nextUid));
            }

            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshBagListView();
            lblStatus.Text = string.Format("✅ 已添加【{0}】×{1:N0}（新开 {2} 格），并写入 [{3}]。", info.Name, amount, newStacksNeeded, currentSlot.SlotName);
        }

        // =========================================================================
        // 8.6 法宝词条
        //   背包 bag.items 里格式编号 2 的是法宝：
        //     alchemy_attrs   = [[属性ID, 数值], ...]          主属性（整数）
        //     alchemy_affixes = [{slot_index, config_id, value(float)}, ...]  词条
        //     pending_alchemy_affixes = 洗练后还没确认的词条
        //   词条定义来自 tbalchemyartifactaffixpool（内置为 affix_db.tsv）
        // =========================================================================
        private ListView lvArtifacts;
        private Label lblArtTitle;
        private Label[] lblArtAttr = new Label[3];
        private NumericUpDown[] numArtAttr = new NumericUpDown[3];
        private ComboBox[] cmbArtAffix = new ComboBox[3];
        private NumericUpDown[] numArtAffix = new NumericUpDown[3];
        private Label[] lblArtAffixRange = new Label[3];
        private CheckBox chkArtAllowOutOfRange;
        private CheckBox chkArtClearPending;
        private Label lblArtPending;
        private long selectedArtifactUid = -1;
        private int selectedArtifactAttrCount = 0;
        private int selectedArtifactAffixCount = 0;
        private static readonly string[] TierNames = { "", "凡阶", "玄阶", "地阶", "天阶" };

        private void BuildArtifactTab(TabPage tab)
        {
            var split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
            Shown += (s, e) => { try { split.SplitterDistance = 430; } catch { } };
            tab.Enter += (s, e) => { try { if (split.SplitterDistance < 300) split.SplitterDistance = 430; } catch { } };

            // 左：法宝列表
            var pnlLeft = split.Panel1;
            pnlLeft.Padding = new Padding(8);
            var lblList = new Label { Text = "背包里的法宝（只有炼制出来的才有词条）", Dock = DockStyle.Top, Height = 26, Font = new Font(Font, FontStyle.Bold) };
            lvArtifacts = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                MultiSelect = false
            };
            lvArtifacts.Columns.Add("名称", 120);
            lvArtifacts.Columns.Add("品阶", 55);
            lvArtifacts.Columns.Add("评分", 50);
            lvArtifacts.Columns.Add("装备中", 55);
            lvArtifacts.Columns.Add("词条", 120);
            lvArtifacts.SelectedIndexChanged += (s, e) =>
            {
                if (lvArtifacts.SelectedItems.Count > 0) SelectArtifact((long)lvArtifacts.SelectedItems[0].Tag);
            };
            pnlLeft.Controls.Add(lvArtifacts);
            pnlLeft.Controls.Add(lblList);

            // 右：编辑区
            var pnlRight = split.Panel2;
            pnlRight.Padding = new Padding(12);
            pnlRight.AutoScroll = true;

            lblArtTitle = new Label { Text = "请在左边选一件法宝", Location = new Point(12, 10), AutoSize = true, Font = new Font(Font.FontFamily, 12f, FontStyle.Bold), ForeColor = Color.FromArgb(25, 65, 120) };

            var grpAttr = new GroupBox { Text = "主属性", Location = new Point(12, 42), Size = new Size(700, 120) };
            for (int i = 0; i < 3; i++)
            {
                lblArtAttr[i] = new Label { Location = new Point(16, 28 + i * 30), Size = new Size(120, 22), Text = "" };
                numArtAttr[i] = new NumericUpDown { Location = new Point(140, 25 + i * 30), Width = 110, Minimum = 0, Maximum = 999999 };
                grpAttr.Controls.Add(lblArtAttr[i]);
                grpAttr.Controls.Add(numArtAttr[i]);
            }

            var grpAffix = new GroupBox { Text = "词条（下拉框选词条，右边填数值）", Location = new Point(12, 172), Size = new Size(700, 160) };
            for (int i = 0; i < 3; i++)
            {
                int idx = i;
                var lbl = new Label { Text = "词条 " + (i + 1) + "：", Location = new Point(16, 30 + i * 40), AutoSize = true };
                cmbArtAffix[i] = new ComboBox { Location = new Point(80, 26 + i * 40), Width = 380, DropDownStyle = ComboBoxStyle.DropDownList, DropDownWidth = 460, MaxDropDownItems = 25 };
                foreach (var a in GameDatabase.AffixList) cmbArtAffix[i].Items.Add(a);
                cmbArtAffix[i].SelectedIndexChanged += (s, e) => UpdateAffixRangeLabel(idx);
                numArtAffix[i] = new NumericUpDown { Location = new Point(470, 26 + i * 40), Width = 90, DecimalPlaces = 2, Increment = 0.1m, Minimum = -9999, Maximum = 9999 };
                lblArtAffixRange[i] = new Label { Location = new Point(568, 30 + i * 40), Size = new Size(125, 22), ForeColor = Color.FromArgb(90, 90, 90) };
                grpAffix.Controls.AddRange(new Control[] { lbl, cmbArtAffix[i], numArtAffix[i], lblArtAffixRange[i] });
            }

            chkArtAllowOutOfRange = new CheckBox { Text = "允许数值超出游戏正常范围（不推荐）", Location = new Point(16, 342), AutoSize = true };
            lblArtPending = new Label { Location = new Point(16, 370), Size = new Size(690, 22), ForeColor = Color.FromArgb(150, 90, 20) };
            chkArtClearPending = new CheckBox { Text = "同时清除这件法宝\"洗练后还没确认\"的词条", Location = new Point(16, 394), AutoSize = true, Checked = true };

            var btnApply = new Button
            {
                Text = "写入这件法宝的修改",
                Location = new Point(16, 428),
                Size = new Size(230, 36),
                BackColor = Color.FromArgb(22, 120, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font(Font, FontStyle.Bold)
            };
            btnApply.Click += (s, e) => ApplyArtifactEdits();

            var lblNote = new Label
            {
                Text = "说明：词条数值按游戏规则限制在该词条的最小~最大值之间；标\"⚠未实装\"的是游戏自己标注还没启用的词条，选了可能没效果。\r\n改词条不会重算评分；要改品阶（会按炼制原型重设主属性和评分）请用下面的按钮。",
                Location = new Point(16, 474),
                Size = new Size(700, 64),
                ForeColor = Color.FromArgb(120, 90, 40)
            };

            // 品阶 / 加词条槽
            var grpTier = new GroupBox { Text = "品阶 && 词条槽（单独写入）", Location = new Point(12, 544), Size = new Size(700, 64) };
            var lblTier = new Label { Text = "品阶：", Location = new Point(14, 28), AutoSize = true };
            cmbArtTier = new ComboBox { Location = new Point(60, 24), Width = 90, DropDownStyle = ComboBoxStyle.DropDownList };
            cmbArtTier.Items.AddRange(new object[] { "凡阶", "玄阶", "地阶", "天阶" });
            var btnTier = new Button { Text = "改品阶（重设主属性和评分）", Location = new Point(160, 21), Size = new Size(230, 30) };
            btnTier.Click += (s, e) => SetArtifactTierAndWrite();
            var btnAddAffix = new Button { Text = "➕ 加一条词条槽（最多 3 条）", Location = new Point(400, 21), Size = new Size(220, 30) };
            btnAddAffix.Click += (s, e) => AddArtifactAffixSlotAndWrite();
            grpTier.Controls.AddRange(new Control[] { lblTier, cmbArtTier, btnTier, btnAddAffix });

            pnlRight.Controls.AddRange(new Control[] { lblArtTitle, grpAttr, grpAffix, chkArtAllowOutOfRange, lblArtPending, chkArtClearPending, btnApply, lblNote, grpTier });
            tab.Controls.Add(split);
            SetArtifactEditorEnabled(false);
        }

        private void SetArtifactEditorEnabled(bool on)
        {
            for (int i = 0; i < 3; i++)
            {
                numArtAttr[i].Enabled = on && i < selectedArtifactAttrCount;
                lblArtAttr[i].Visible = numArtAttr[i].Visible = i < selectedArtifactAttrCount;
                cmbArtAffix[i].Enabled = numArtAffix[i].Enabled = on && i < selectedArtifactAffixCount;
            }
        }

        private void UpdateAffixRangeLabel(int i)
        {
            var a = cmbArtAffix[i].SelectedItem as AffixInfo;
            lblArtAffixRange[i].Text = a == null ? "" : string.Format("范围 {0} ~ {1}", a.Min, a.Max);
        }

        private IEnumerable<MsgPackNode> EnumerateArtifactCells()
        {
            var items = GetBagItemsNode();
            if (items == null) yield break;
            foreach (var cell in items.ArrayItems)
            {
                if (cell.Kind != MsgPackKind.Array || cell.ArrayItems == null || cell.ArrayItems.Count < 2) continue;
                if (cell.ArrayItems[0].AsInt64(-1) != 2 || cell.ArrayItems[1].Kind != MsgPackKind.Map) continue;
                yield return cell.ArrayItems[1];
            }
        }

        private MsgPackNode FindArtifactByUid(long uid)
        {
            foreach (var m in EnumerateArtifactCells())
            {
                var u = m.GetMapValue("uid");
                if (u != null && u.AsInt64(-1) == uid) return m;
            }
            return null;
        }

        private string DescribeAffix(MsgPackNode affix)
        {
            var cid = affix.GetMapValue("config_id");
            var val = affix.GetMapValue("value");
            AffixInfo a;
            if (cid == null || !GameDatabase.Affixes.TryGetValue(cid.AsInt32(0), out a)) return "?";
            double v = val != null ? val.AsDouble(0) : 0;
            return a.DescTemplate.Replace("{0}", v.ToString("0.##"));
        }

        private void RefreshArtifactList()
        {
            if (lvArtifacts == null) return;
            long keep = selectedArtifactUid;
            lvArtifacts.BeginUpdate();
            lvArtifacts.Items.Clear();
            foreach (var m in EnumerateArtifactCells())
            {
                int iid = m.GetMapValue("item_id") != null ? m.GetMapValue("item_id").AsInt32(0) : 0;
                long uid = m.GetMapValue("uid") != null ? m.GetMapValue("uid").AsInt64(-1) : -1;
                bool crafted = m.GetMapValue("alchemy_crafted") != null && m.GetMapValue("alchemy_crafted").AsBool(false);
                int tier = m.GetMapValue("alchemy_tier_id") != null ? m.GetMapValue("alchemy_tier_id").AsInt32(0) : 0;
                long score = m.GetMapValue("alchemy_score") != null ? m.GetMapValue("alchemy_score").AsInt64(0) : 0;
                bool eq = m.GetMapValue("is_equipped") != null && m.GetMapValue("is_equipped").AsBool(false);
                ItemInfo info;
                GameDatabase.Items.TryGetValue(iid, out info);
                var affixes = m.GetMapValue("alchemy_affixes");
                string affText = "";
                if (affixes != null && affixes.Kind == MsgPackKind.Array && affixes.ArrayItems != null)
                    affText = string.Join(" / ", affixes.ArrayItems.Where(x => x.Kind == MsgPackKind.Map).Select(DescribeAffix));

                var lvi = new ListViewItem(info != null ? info.Name : ("法宝" + iid)) { Tag = uid };
                lvi.SubItems.Add(crafted ? (tier > 0 && tier < TierNames.Length ? TierNames[tier] : tier.ToString()) : "未炼制");
                lvi.SubItems.Add(crafted ? score.ToString() : "—");
                lvi.SubItems.Add(eq ? "是" : "");
                lvi.SubItems.Add(crafted ? affText : "（无词条）");
                if (!crafted) lvi.ForeColor = Color.Gray;
                lvArtifacts.Items.Add(lvi);
                if (uid == keep) lvi.Selected = true;
            }
            lvArtifacts.EndUpdate();
            if (lvArtifacts.SelectedItems.Count == 0)
            {
                selectedArtifactUid = -1;
                selectedArtifactAttrCount = selectedArtifactAffixCount = 0;
                lblArtTitle.Text = "请在左边选一件法宝";
                lblArtPending.Text = "";
                SetArtifactEditorEnabled(false);
            }
        }

        private void SelectArtifact(long uid)
        {
            var m = FindArtifactByUid(uid);
            if (m == null) return;
            selectedArtifactUid = uid;
            int iid = m.GetMapValue("item_id") != null ? m.GetMapValue("item_id").AsInt32(0) : 0;
            ItemInfo info;
            GameDatabase.Items.TryGetValue(iid, out info);
            bool crafted = m.GetMapValue("alchemy_crafted") != null && m.GetMapValue("alchemy_crafted").AsBool(false);
            int tier = m.GetMapValue("alchemy_tier_id") != null ? m.GetMapValue("alchemy_tier_id").AsInt32(0) : 0;
            long score = m.GetMapValue("alchemy_score") != null ? m.GetMapValue("alchemy_score").AsInt64(0) : 0;

            lblArtTitle.Text = string.Format("{0}  {1}", info != null ? info.Name : ("法宝" + iid),
                crafted ? string.Format("（{0}，评分 {1}）", tier > 0 && tier < TierNames.Length ? TierNames[tier] : tier.ToString(), score) : "（未炼制，没有词条）");

            // 主属性
            var attrs = m.GetMapValue("alchemy_attrs");
            selectedArtifactAttrCount = 0;
            if (attrs != null && attrs.Kind == MsgPackKind.Array && attrs.ArrayItems != null)
            {
                foreach (var pair in attrs.ArrayItems)
                {
                    if (selectedArtifactAttrCount >= 3) break;
                    if (pair.Kind != MsgPackKind.Array || pair.ArrayItems == null || pair.ArrayItems.Count < 2) continue;
                    int i = selectedArtifactAttrCount++;
                    lblArtAttr[i].Text = GameDatabase.AttrName(pair.ArrayItems[0].AsInt32(0)) + "：";
                    numArtAttr[i].Value = (decimal)Math.Max(0, Math.Min(999999, pair.ArrayItems[1].AsDouble(0)));
                }
            }

            // 词条
            var affixes = m.GetMapValue("alchemy_affixes");
            selectedArtifactAffixCount = 0;
            for (int i = 0; i < 3; i++) { cmbArtAffix[i].SelectedIndex = -1; numArtAffix[i].Value = 0; lblArtAffixRange[i].Text = ""; }
            if (affixes != null && affixes.Kind == MsgPackKind.Array && affixes.ArrayItems != null)
            {
                foreach (var af in affixes.ArrayItems.Where(x => x.Kind == MsgPackKind.Map).OrderBy(x => x.GetMapValue("slot_index") != null ? x.GetMapValue("slot_index").AsInt32(0) : 0))
                {
                    if (selectedArtifactAffixCount >= 3) break;
                    int i = selectedArtifactAffixCount++;
                    int cid = af.GetMapValue("config_id") != null ? af.GetMapValue("config_id").AsInt32(0) : 0;
                    AffixInfo a;
                    if (GameDatabase.Affixes.TryGetValue(cid, out a)) cmbArtAffix[i].SelectedItem = a;
                    double v = af.GetMapValue("value") != null ? af.GetMapValue("value").AsDouble(0) : 0;
                    numArtAffix[i].Value = (decimal)Math.Round(Math.Max(-9999, Math.Min(9999, v)), 2);
                    UpdateAffixRangeLabel(i);
                }
            }

            var pending = m.GetMapValue("pending_alchemy_affixes");
            int pendingCount = (pending != null && pending.Kind == MsgPackKind.Array && pending.ArrayItems != null) ? pending.ArrayItems.Count : 0;
            lblArtPending.Text = pendingCount > 0
                ? string.Format("这件法宝有 {0} 条洗练后还没确认的词条：{1}", pendingCount, string.Join(" / ", pending.ArrayItems.Where(x => x.Kind == MsgPackKind.Map).Select(DescribeAffix)))
                : "";
            chkArtClearPending.Visible = pendingCount > 0;

            SetArtifactEditorEnabled(crafted);
            if (cmbArtTier != null) cmbArtTier.SelectedIndex = crafted && tier >= 1 && tier <= 4 ? tier - 1 : -1;
        }

        private void ApplyArtifactEdits()
        {
            if (currentSlot == null || selectedArtifactUid < 0) { MessageBox.Show(this, "请先在左边选一件法宝。", "提示"); return; }

            // 先在界面上检查
            var chosen = new AffixInfo[3];
            for (int i = 0; i < selectedArtifactAffixCount; i++)
            {
                chosen[i] = cmbArtAffix[i].SelectedItem as AffixInfo;
                if (chosen[i] == null) { MessageBox.Show(this, string.Format("词条 {0} 没有选择。", i + 1), "提示"); return; }
                double v = (double)numArtAffix[i].Value;
                if (!chkArtAllowOutOfRange.Checked && (v < chosen[i].Min - 1e-6 || v > chosen[i].Max + 1e-6))
                {
                    MessageBox.Show(this, string.Format("词条 {0} 的数值 {1} 超出了这个词条的正常范围（{2} ~ {3}）。\n要么改数值，要么勾选\"允许数值超出游戏正常范围\"。",
                        i + 1, v, chosen[i].Min, chosen[i].Max), "超出范围");
                    return;
                }
            }

            long uid = selectedArtifactUid;
            ReloadIfDiskChanged();
            var m = FindArtifactByUid(uid);
            if (m == null) { MessageBox.Show(this, "在最新的存档里找不到这件法宝了，请刷新后再试。", "提示"); RefreshArtifactList(); return; }

            // 主属性
            var attrs = m.GetMapValue("alchemy_attrs");
            if (attrs != null && attrs.Kind == MsgPackKind.Array && attrs.ArrayItems != null)
            {
                int i = 0;
                foreach (var pair in attrs.ArrayItems)
                {
                    if (i >= selectedArtifactAttrCount) break;
                    if (pair.Kind != MsgPackKind.Array || pair.ArrayItems == null || pair.ArrayItems.Count < 2) continue;
                    long nv = (long)numArtAttr[i].Value;
                    var valNode = pair.ArrayItems[1];
                    if (valNode.Kind == MsgPackKind.Float || valNode.Kind == MsgPackKind.Double)
                    {
                        if (Math.Abs(valNode.FloatVal - nv) > 1e-6) { valNode.FloatVal = nv; valNode.MarkModified(); }
                    }
                    else if (valNode.AsInt64(long.MinValue) != nv) valNode.SetIntValue(nv);
                    i++;
                }
            }

            // 词条
            var affixes = m.GetMapValue("alchemy_affixes");
            if (affixes != null && affixes.Kind == MsgPackKind.Array && affixes.ArrayItems != null)
            {
                var ordered = affixes.ArrayItems.Where(x => x.Kind == MsgPackKind.Map)
                    .OrderBy(x => x.GetMapValue("slot_index") != null ? x.GetMapValue("slot_index").AsInt32(0) : 0).ToList();
                for (int i = 0; i < ordered.Count && i < selectedArtifactAffixCount; i++)
                {
                    var af = ordered[i];
                    var cidNode = af.GetMapValue("config_id");
                    if (cidNode == null || cidNode.AsInt32(0) != chosen[i].Id)
                    {
                        if (cidNode != null) cidNode.SetIntValue(chosen[i].Id);
                        else af.SetMapValue("config_id", MsgPackNode.CreateInt(chosen[i].Id));
                    }
                    float nv = (float)numArtAffix[i].Value;
                    var vNode = af.GetMapValue("value");
                    if (vNode == null || Math.Abs(vNode.AsDouble(0) - nv) > 0.0001)
                        af.SetMapValue("value", MsgPackNode.CreateFloat(nv));
                }
            }

            // 洗练后未确认的词条
            var pending = m.GetMapValue("pending_alchemy_affixes");
            if (chkArtClearPending.Visible && chkArtClearPending.Checked && pending != null && pending.Kind == MsgPackKind.Array && pending.ArrayItems != null && pending.ArrayItems.Count > 0)
            {
                pending.ArrayItems.Clear();
                pending.MarkModified();
            }

            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshArtifactList();
            SelectArtifact(uid);
            lblStatus.Text = string.Format("✅ 已写入法宝【{0}】的属性和词条到 [{1}]。", lblArtTitle.Text.Split(' ')[0], currentSlot.SlotName);
        }

        // =========================================================================
        // 8.7 其他功能
        // =========================================================================
        private static MsgPackNode CreateNil() { return new MsgPackNode { Kind = MsgPackKind.Nil, IsModified = true }; }

        // 设置整数键的 Map 值（没有就新增）
        private static void SetIntKeyValue(MsgPackNode map, long key, MsgPackNode val)
        {
            for (int i = 0; i < map.MapEntries.Count; i++)
            {
                var k = map.MapEntries[i].Key;
                if ((k.Kind == MsgPackKind.Int || k.Kind == MsgPackKind.UInt) && k.AsInt64(long.MinValue) == key)
                {
                    val.Parent = map;
                    map.MapEntries[i] = new KeyValuePair<MsgPackNode, MsgPackNode>(k, val);
                    map.MarkModified();
                    return;
                }
            }
            var kn = MsgPackNode.CreateInt(key);
            kn.Parent = map; val.Parent = map;
            map.MapEntries.Add(new KeyValuePair<MsgPackNode, MsgPackNode>(kn, val));
            map.MarkModified();
        }

        // ---------------- 通用属性加成 ----------------
        // 返回：基础, 成长, 真实永久加成合计, 本工具加成合计
        private double[] GetAttrBreakdown(int attrId)
        {
            var r = new double[4];
            var c = GetCombatNode();
            if (c == null) return null;
            var b = c.GetMapValue("base_attrs");
            var g = c.GetMapValue("growth_attrs");
            var bv = b != null ? b.GetMapValueByInt(attrId) : null;
            var gv = g != null ? g.GetMapValueByInt(attrId) : null;
            r[0] = bv != null ? bv.AsDouble(0) : 0;
            r[1] = gv != null ? gv.AsDouble(0) : 0;
            var pa = c.GetMapValue("permanent_attrs");
            var list = pa != null ? pa.GetMapValueByInt(attrId) : null;
            if (list != null && list.Kind == MsgPackKind.Array && list.ArrayItems != null)
            {
                foreach (var e in list.ArrayItems)
                {
                    if (e.Kind != MsgPackKind.Array || e.ArrayItems == null || e.ArrayItems.Count < 5) continue;
                    double v = e.ArrayItems[4].AsDouble(0);
                    if (IsEditorModifier(e)) r[3] += v; else r[2] += v;
                }
            }
            return r;
        }

        // 把某个属性的"存档修改器"加成设成 value（0 = 删除）。返回是否成功（不写盘）
        private bool SetEditorAttrModifier(int attrId, double value)
        {
            var c = GetCombatNode();
            if (c == null) return false;
            var pa = c.GetMapValue("permanent_attrs");
            if (pa == null || pa.Kind != MsgPackKind.Map) return false;
            var list = pa.GetMapValueByInt(attrId);
            if (list == null || list.Kind != MsgPackKind.Array)
            {
                list = MsgPackNode.CreateArray();
                SetIntKeyValue(pa, attrId, list);
            }
            list.ArrayItems.RemoveAll(IsEditorModifier);
            if (Math.Abs(value) > 1e-7)
            {
                var entry = MsgPackNode.CreateArray(new List<MsgPackNode>
                {
                    MsgPackNode.CreateInt(5),
                    MsgPackNode.CreateString("item:220004"),
                    MsgPackNode.CreateString("item:0:" + Guid.NewGuid().ToString("N")),
                    MsgPackNode.CreateInt(attrId),
                    MsgPackNode.CreateFloat((float)value),
                    MsgPackNode.CreateInt(DateTime.Now.Ticks),
                    MsgPackNode.CreateString(EditorModifierName)
                });
                entry.Parent = list;
                list.ArrayItems.Add(entry);
            }
            list.MarkModified();
            return true;
        }

        private static readonly HashSet<int> PercentAttrs = new HashSet<int> { 11, 12, 13, 101, 102, 103, 104, 108, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 51, 52, 53, 54, 55 };

        private ListView lvAttrs;
        private NumericUpDown numAttrMod;
        private Label lblAttrHint;
        private NumericUpDown numEnergy;
        private Label lblEnergyInfo;

        private void BuildAttrTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10) };
            var top = new Label
            {
                Dock = DockStyle.Top, Height = 44, ForeColor = Color.FromArgb(45, 75, 110),
                Text = "每个属性 = 基础 + 成长 + 永久加成（吃果子、丹药、突破材料等）+ 本工具加成。这里只增删一条显示名为\"存档修改器\"的加成，不动你真实获得的加成。\r\n" +
                       "百分比类属性（暴击率、暴击伤害、伤害加成等）用小数表示：0.1 = 10%。道途、天赋、装备等加成由游戏实时计算，不在这里。"
            };
            lvAttrs = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = false };
            foreach (var col in new[] { "属性", "ID", "基础", "成长", "永久加成", "本工具加成", "合计" }) lvAttrs.Columns.Add(col, col == "属性" ? 130 : 95);
            lvAttrs.SelectedIndexChanged += (s, e) =>
            {
                if (lvAttrs.SelectedItems.Count == 0) return;
                int id = (int)lvAttrs.SelectedItems[0].Tag;
                var b = GetAttrBreakdown(id);
                if (b != null) numAttrMod.Value = (decimal)Math.Max(-99999, Math.Min(99999, Math.Round(b[3], 3)));
                lblAttrHint.Text = PercentAttrs.Contains(id) ? "这是百分比属性：0.1 = 10%" : "";
            };

            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 96 };
            var lblMod = new Label { Text = "选中属性的本工具加成：", Location = new Point(2, 14), AutoSize = true };
            numAttrMod = new NumericUpDown { Location = new Point(160, 10), Width = 110, DecimalPlaces = 3, Increment = 1, Minimum = -99999, Maximum = 99999 };
            var btnMod = new Button { Text = "写入加成", Location = new Point(280, 7), Size = new Size(120, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnMod.Click += (s, e) => SetSelectedAttrModAndWrite();
            var btnClear = new Button { Text = "清除全部本工具加成", Location = new Point(408, 7), Size = new Size(150, 30) };
            btnClear.Click += (s, e) => ClearAllEditorAttrModsAndWrite();
            lblAttrHint = new Label { Location = new Point(570, 14), AutoSize = true, ForeColor = Color.FromArgb(150, 90, 20) };

            var lblEn = new Label { Text = "当前精力：", Location = new Point(2, 58), AutoSize = true };
            numEnergy = new NumericUpDown { Location = new Point(160, 54), Width = 110, Minimum = 0, Maximum = 99999 };
            var btnEn = new Button { Text = "写入精力", Location = new Point(280, 51), Size = new Size(120, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnEn.Click += (s, e) => SetEnergyAndWrite();
            lblEnergyInfo = new Label { Location = new Point(408, 58), AutoSize = true, ForeColor = Color.FromArgb(45, 75, 110) };
            bottom.Controls.AddRange(new Control[] { lblMod, numAttrMod, btnMod, btnClear, lblAttrHint, lblEn, numEnergy, btnEn, lblEnergyInfo });

            pnl.Controls.Add(lvAttrs);
            pnl.Controls.Add(bottom);
            pnl.Controls.Add(top);
            tab.Controls.Add(pnl);
        }

        private void RefreshAttrTab()
        {
            if (lvAttrs == null) return;
            int keep = lvAttrs.SelectedItems.Count > 0 ? (int)lvAttrs.SelectedItems[0].Tag : -1;
            lvAttrs.BeginUpdate();
            lvAttrs.Items.Clear();
            var c = GetCombatNode();
            var ids = new SortedSet<int>();
            if (c != null)
            {
                foreach (var name in new[] { "base_attrs", "permanent_attrs" })
                {
                    var m = c.GetMapValue(name);
                    if (m != null && m.Kind == MsgPackKind.Map)
                        foreach (var kv in m.MapEntries) ids.Add(kv.Key.AsInt32(0));
                }
            }
            foreach (var id in ids)
            {
                if (id == 200 || id == 201) continue; // 精力单独处理
                var b = GetAttrBreakdown(id);
                if (b == null) continue;
                var lvi = new ListViewItem(GameDatabase.AttrName(id)) { Tag = id };
                lvi.SubItems.Add(id.ToString());
                foreach (var v in new[] { b[0], b[1], b[2], b[3], b[0] + b[1] + b[2] + b[3] }) lvi.SubItems.Add(v.ToString("0.###"));
                if (Math.Abs(b[3]) > 1e-7) lvi.BackColor = Color.FromArgb(225, 248, 230);
                lvAttrs.Items.Add(lvi);
                if (id == keep) lvi.Selected = true;
            }
            lvAttrs.EndUpdate();

            var cur = GetAttrBreakdown(200);
            var max = GetAttrBreakdown(201);
            if (cur != null)
            {
                numEnergy.Value = (decimal)Math.Max(0, Math.Min(99999, Math.Round(cur[0])));
                double maxTotal = max != null ? max[0] + max[1] + max[2] + max[3] : 0;
                lblEnergyInfo.Text = string.Format("精力上限（基础+加成）约 {0:0}", maxTotal);
            }
        }

        private void SetSelectedAttrModAndWrite()
        {
            if (currentSlot == null || lvAttrs.SelectedItems.Count == 0) { MessageBox.Show(this, "请先在列表里选一个属性。", "提示"); return; }
            int id = (int)lvAttrs.SelectedItems[0].Tag;
            double v = (double)numAttrMod.Value;
            ReloadIfDiskChanged();
            if (!SetEditorAttrModifier(id, v)) { MessageBox.Show(this, "存档里没找到属性数据。", "错误"); return; }
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已把【{0}】的本工具加成设为 {1}，并写入 [{2}]。", GameDatabase.AttrName(id), v, currentSlot.SlotName);
        }

        private void ClearAllEditorAttrModsAndWrite()
        {
            if (currentSlot == null) return;
            if (MessageBox.Show(this, "确定要清除所有属性上的\"存档修改器\"加成吗？（包括魅力）", "确认", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
            ReloadIfDiskChanged();
            var c = GetCombatNode();
            var pa = c != null ? c.GetMapValue("permanent_attrs") : null;
            int removed = 0;
            if (pa != null && pa.Kind == MsgPackKind.Map)
                foreach (var kv in pa.MapEntries)
                    if (kv.Value.Kind == MsgPackKind.Array && kv.Value.ArrayItems != null)
                    {
                        int n = kv.Value.ArrayItems.RemoveAll(IsEditorModifier);
                        if (n > 0) { removed += n; kv.Value.MarkModified(); }
                    }
            if (removed == 0) { lblStatus.Text = "没有需要清除的本工具加成。"; return; }
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已清除 {0} 条本工具加成，并写入 [{1}]。", removed, currentSlot.SlotName);
        }

        private void SetEnergyAndWrite()
        {
            if (currentSlot == null) return;
            double v = (double)numEnergy.Value;
            ReloadIfDiskChanged();
            var c = GetCombatNode();
            var b = c != null ? c.GetMapValue("base_attrs") : null;
            var node = b != null ? b.GetMapValueByInt(200) : null;
            if (node == null) { MessageBox.Show(this, "存档里没找到精力数据。", "错误"); return; }
            if (node.Kind == MsgPackKind.Float || node.Kind == MsgPackKind.Double) { node.FloatVal = v; node.MarkModified(); }
            else node.SetIntValue((long)v);
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已把当前精力改为 {0}，并写入 [{1}]。", v, currentSlot.SlotName);
        }

        // ---------------- 声望 / 货币 / 迷雾 / 炼丹 ----------------
        private ListView lvRep;
        private NumericUpDown numRep;
        private ComboBox cmbPillLevel;
        private ComboBox cmbFurnace;
        private Label lblPillInfo;
        private Label lblFogInfo;
        private ComboBox cmbForgeLevel;
        private NumericUpDown numForgePoints;
        private CheckedListBox clbForgeTalents;
        private Label lblForgeInfo;

        private MsgPackNode GetForgeNode()
        {
            var pm = GetPlayerModelNode();
            var a = pm != null ? pm.GetMapValue("alchemy") : null;
            return (a != null && a.Kind == MsgPackKind.Map) ? a : null;
        }

        private void RefreshForgeUI()
        {
            if (cmbForgeLevel == null) return;
            var a = GetForgeNode();
            if (a == null) { lblForgeInfo.Text = "存档里没找到炼器数据。"; return; }
            int lv = a.GetMapValue("alchemy_level") != null ? a.GetMapValue("alchemy_level").AsInt32(1) : 1;
            long exp = a.GetMapValue("alchemy_exp") != null ? a.GetMapValue("alchemy_exp").AsInt64(0) : 0;
            long pts = a.GetMapValue("alchemy_talent_points") != null ? a.GetMapValue("alchemy_talent_points").AsInt64(0) : 0;
            var fl = MiscDatabase.ForgeLevels.FirstOrDefault(x => x.Level == lv);
            if (fl != null) cmbForgeLevel.SelectedItem = fl;
            numForgePoints.Value = Math.Max(0, Math.Min(99999, pts));
            var learned = new HashSet<long>();
            var ln = a.GetMapValue("alchemy_learned_talents");
            if (ln != null && ln.Kind == MsgPackKind.Array) foreach (var x in ln.ArrayItems) learned.Add(x.AsInt64(0));
            for (int i = 0; i < clbForgeTalents.Items.Count; i++)
                clbForgeTalents.SetItemChecked(i, learned.Contains(((ForgeTalentInfo)clbForgeTalents.Items[i]).Id));
            lblForgeInfo.Text = string.Format("当前：{0} 级（经验 {1}），天赋点 {2}，已学天赋 {3} 个。", lv, exp, pts, learned.Count);
        }

        private void SetForgeAndWrite()
        {
            if (currentSlot == null) return;
            var fl = cmbForgeLevel.SelectedItem as ForgeLevelInfo;
            if (fl == null) return;
            long pts = (long)numForgePoints.Value;
            var learnedIds = new List<int>();
            for (int i = 0; i < clbForgeTalents.Items.Count; i++)
                if (clbForgeTalents.GetItemChecked(i)) learnedIds.Add(((ForgeTalentInfo)clbForgeTalents.Items[i]).Id);
            ReloadIfDiskChanged();
            var a = GetForgeNode();
            if (a == null) { MessageBox.Show(this, "存档里没找到炼器数据。", "错误"); return; }

            var lvNode = a.GetMapValue("alchemy_level");
            int oldLv = lvNode != null ? lvNode.AsInt32(1) : 1;
            if (oldLv != fl.Level)
            {
                if (lvNode != null) lvNode.SetIntValue(fl.Level); else a.SetMapValue("alchemy_level", MsgPackNode.CreateInt(fl.Level));
                var expNode = a.GetMapValue("alchemy_exp");
                if (expNode != null) expNode.SetIntValue(0); else a.SetMapValue("alchemy_exp", MsgPackNode.CreateInt(0));   // 换级后本级经验从 0 开始
            }
            var ptNode = a.GetMapValue("alchemy_talent_points");
            if (ptNode != null) { if (ptNode.AsInt64(-1) != pts) ptNode.SetIntValue(pts); }
            else a.SetMapValue("alchemy_talent_points", MsgPackNode.CreateInt(pts));

            // 已解锁天赋 = 当前等级及以下各级解锁的天赋 + 已学的天赋
            var unlocked = new SortedSet<int>(MiscDatabase.ForgeLevels.Where(x => x.Level <= fl.Level).SelectMany(x => x.Unlocks));
            foreach (var id in learnedIds) unlocked.Add(id);
            a.SetMapValue("alchemy_unlocked_talents", MsgPackNode.CreateArray(unlocked.Select(x => MsgPackNode.CreateInt(x)).ToList()));

            // 已学天赋：保留原来的顺序，去掉取消勾选的，新勾的加在后面
            var ln = a.GetMapValue("alchemy_learned_talents");
            var order = new List<int>();
            if (ln != null && ln.Kind == MsgPackKind.Array) foreach (var x in ln.ArrayItems) { int v = x.AsInt32(0); if (learnedIds.Contains(v) && !order.Contains(v)) order.Add(v); }
            foreach (var id in learnedIds) if (!order.Contains(id)) order.Add(id);
            bool learnedChanged = ln == null || ln.Kind != MsgPackKind.Array || !ln.ArrayItems.Select(x => x.AsInt32(0)).SequenceEqual(order);
            if (learnedChanged) a.SetMapValue("alchemy_learned_talents", MsgPackNode.CreateArray(order.Select(x => MsgPackNode.CreateInt(x)).ToList()));

            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已写入炼器：{0} 级 {1}，天赋点 {2}，已学天赋 {3} 个，并写入 [{4}]。", fl.Level, fl.Title, pts, order.Count, currentSlot.SlotName);
        }
        private static readonly int[] CurrencyItemIds = { 50000, 50002, 50001 };

        private void BuildRepTab(TabPage tab)
        {
            var split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel2 };
            Shown += (s, e) => { try { split.SplitterDistance = Math.Max(300, split.Width - 470); } catch { } };

            var pnlL = split.Panel1; pnlL.Padding = new Padding(8);
            var lblL = new Label { Text = "货币与声望（选中一行，在下面填新数值）", Dock = DockStyle.Top, Height = 24, Font = new Font(Font, FontStyle.Bold) };
            lvRep = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = false };
            lvRep.Columns.Add("类别", 90); lvRep.Columns.Add("名称", 150); lvRep.Columns.Add("当前值", 120); lvRep.Columns.Add("范围", 160);
            lvRep.SelectedIndexChanged += (s, e) =>
            {
                if (lvRep.SelectedItems.Count == 0) return;
                var tag = (object[])lvRep.SelectedItems[0].Tag;
                long min = (long)tag[2], max = (long)tag[3], cur = (long)tag[4];
                numRep.Minimum = min; numRep.Maximum = max;
                numRep.Value = Math.Max(min, Math.Min(max, cur));
            };
            var bot = new Panel { Dock = DockStyle.Bottom, Height = 46 };
            var lblN = new Label { Text = "新数值：", Location = new Point(2, 16), AutoSize = true };
            numRep = new NumericUpDown { Location = new Point(64, 12), Width = 130, Minimum = -999999999, Maximum = 999999999, ThousandsSeparator = true };
            var btnRep = new Button { Text = "写入", Location = new Point(204, 9), Size = new Size(100, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnRep.Click += (s, e) => SetSelectedRepAndWrite();
            bot.Controls.AddRange(new Control[] { lblN, numRep, btnRep });
            pnlL.Controls.Add(lvRep); pnlL.Controls.Add(bot); pnlL.Controls.Add(lblL);

            var pnlR = split.Panel2; pnlR.Padding = new Padding(8);
            var grpFog = new GroupBox { Text = "🗺 地图迷雾", Location = new Point(8, 8), Size = new Size(440, 100) };
            lblFogInfo = new Label { Location = new Point(14, 26), Size = new Size(410, 22) };
            var btnFog = new Button { Text = "地图迷雾全开", Location = new Point(14, 54), Size = new Size(160, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnFog.Click += (s, e) => RevealFogAndWrite();
            grpFog.Controls.AddRange(new Control[] { lblFogInfo, btnFog });

            var grpPill = new GroupBox { Text = "⚗ 炼丹等级 && 丹炉", Location = new Point(8, 118), Size = new Size(440, 190) };
            var l1 = new Label { Text = "炼丹等级：", Location = new Point(14, 30), AutoSize = true };
            cmbPillLevel = new ComboBox { Location = new Point(90, 26), Width = 220, DropDownStyle = ComboBoxStyle.DropDownList };
            foreach (var pl in MiscDatabase.PillLevels) cmbPillLevel.Items.Add(pl);
            var l2 = new Label { Text = "已解锁丹炉：", Location = new Point(14, 64), AutoSize = true };
            cmbFurnace = new ComboBox { Location = new Point(90, 60), Width = 220, DropDownStyle = ComboBoxStyle.DropDownList };
            foreach (var f in MiscDatabase.Furnaces) cmbFurnace.Items.Add(f);
            var btnPill = new Button { Text = "写入炼丹等级和丹炉", Location = new Point(14, 96), Size = new Size(190, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnPill.Click += (s, e) => SetPillLevelAndWrite();
            lblPillInfo = new Label { Location = new Point(14, 132), Size = new Size(415, 52), ForeColor = Color.FromArgb(45, 75, 110) };
            grpPill.Controls.AddRange(new Control[] { l1, cmbPillLevel, l2, cmbFurnace, btnPill, lblPillInfo });

            // 炼器等级 / 天赋点 / 炼器天赋
            var grpForge = new GroupBox { Text = "⚒ 炼器等级 && 炼器天赋", Location = new Point(8, 318), Size = new Size(440, 330) };
            var lf1 = new Label { Text = "炼器等级：", Location = new Point(14, 30), AutoSize = true };
            cmbForgeLevel = new ComboBox { Location = new Point(90, 26), Width = 180, DropDownStyle = ComboBoxStyle.DropDownList };
            foreach (var fl in MiscDatabase.ForgeLevels) cmbForgeLevel.Items.Add(fl);
            var lf2 = new Label { Text = "天赋点：", Location = new Point(284, 30), AutoSize = true };
            numForgePoints = new NumericUpDown { Location = new Point(340, 26), Width = 80, Minimum = 0, Maximum = 99999 };
            var lf3 = new Label { Text = "已学炼器天赋（打勾 = 已学）：", Location = new Point(14, 62), AutoSize = true };
            clbForgeTalents = new CheckedListBox { Location = new Point(14, 82), Size = new Size(412, 180), CheckOnClick = true, HorizontalScrollbar = true };
            foreach (var ft in MiscDatabase.ForgeTalents) clbForgeTalents.Items.Add(ft);
            var btnForge = new Button { Text = "写入炼器等级、天赋点和天赋", Location = new Point(14, 270), Size = new Size(230, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnForge.Click += (s, e) => SetForgeAndWrite();
            var btnForgeAll = new Button { Text = "全部勾上", Location = new Point(252, 270), Size = new Size(90, 30) };
            btnForgeAll.Click += (s, e) => { for (int i = 0; i < clbForgeTalents.Items.Count; i++) clbForgeTalents.SetItemChecked(i, true); };
            lblForgeInfo = new Label { Location = new Point(14, 304), Size = new Size(415, 22), ForeColor = Color.FromArgb(45, 75, 110) };
            grpForge.Controls.AddRange(new Control[] { lf1, cmbForgeLevel, lf2, numForgePoints, lf3, clbForgeTalents, btnForge, btnForgeAll, lblForgeInfo });
            // 炼丹 / 炼器搬到单独的【炼丹 / 炼器】页
            pillGroupForMove = grpPill;
            forgeGroupForMove = grpForge;
            pnlR.AutoScroll = true;

            var lblNote = new Label
            {
                Location = new Point(8, 118), Size = new Size(440, 60), ForeColor = Color.FromArgb(120, 90, 40),
                Text = "炼丹等级、丹炉、炼丹天赋、丹方图鉴和炼器，在左侧【炼丹 / 炼器】页。"
            };
            pnlR.Controls.AddRange(new Control[] { grpFog, lblNote, BuildDifficultyGroup() });
            tab.Controls.Add(split);
        }

        private GroupBox pillGroupForMove;
        private GroupBox forgeGroupForMove;

        private long GetBagItemTotal(int itemId)
        {
            long total = 0;
            var items = GetBagItemsNode();
            if (items == null) return 0;
            foreach (var cell in items.ArrayItems)
            {
                if (cell.Kind != MsgPackKind.Array || cell.ArrayItems == null || cell.ArrayItems.Count < 2) continue;
                var m = cell.ArrayItems[1];
                if (m.Kind != MsgPackKind.Map) continue;
                var id = m.GetMapValue("item_id");
                if (id != null && id.AsInt32(0) == itemId) total += m.GetMapValue("count") != null ? m.GetMapValue("count").AsInt64(0) : 0;
            }
            return total;
        }

        private void RefreshRepTab()
        {
            if (lvRep == null) return;
            int keepIdx = lvRep.SelectedIndices.Count > 0 ? lvRep.SelectedIndices[0] : -1;
            lvRep.BeginUpdate();
            lvRep.Items.Clear();
            Action<string, string, string, long, long, long, int> add = (cat, name, key, min, max, cur, id) =>
            {
                var lvi = new ListViewItem(cat) { Tag = new object[] { key, id, min, max, cur } };
                lvi.SubItems.Add(name); lvi.SubItems.Add(cur.ToString("N0")); lvi.SubItems.Add(string.Format("{0:N0} ~ {1:N0}", min, max));
                lvRep.Items.Add(lvi);
            };
            foreach (var iid in CurrencyItemIds)
            {
                ItemInfo info; GameDatabase.Items.TryGetValue(iid, out info);
                add("货币", info != null ? info.Name : iid.ToString(), "item", 0, 999999999, GetBagItemTotal(iid), iid);
            }
            var bv = GetBehaviorValueNode();
            var city = bv != null ? bv.GetMapValue("city_reputes") : null;
            var sect = bv != null ? bv.GetMapValue("sect_reputes") : null;
            foreach (var t in MiscDatabase.Towns.OrderBy(x => x.Key))
            {
                var v = city != null ? city.GetMapValueByInt(t.Key) : null;
                add("城镇声望", t.Value, "city", 0, 999999, v != null ? v.AsInt64(0) : 0, t.Key);
            }
            foreach (var s in MiscDatabase.Sects.OrderBy(x => x.Key))
            {
                var v = sect != null ? sect.GetMapValueByInt(s.Key) : null;
                add("宗门声望", s.Value, "sect", -999999, 999999, v != null ? v.AsInt64(0) : 0, s.Key);
            }
            lvRep.EndUpdate();
            if (keepIdx >= 0 && keepIdx < lvRep.Items.Count) lvRep.Items[keepIdx].Selected = true;

            // 迷雾
            var pm = GetPlayerModelNode();
            var fog = pm != null ? pm.GetMapValue("map_fog_seen_regions") : null;
            var seen = fog != null ? fog.GetMapValueByInt(200) : null;
            int seenCount = seen != null && seen.ArrayItems != null ? seen.ArrayItems.Count : 0;
            lblFogInfo.Text = string.Format("世界地图共 {0} 块迷雾区域，已揭开 {1} 块。", FogRegionIds.Length, seenCount);

            // 炼丹
            var rp = pm != null ? pm.GetMapValue("refining_pills") : null;
            int lv = rp != null && rp.GetMapValue("rp_level") != null ? rp.GetMapValue("rp_level").AsInt32(1) : 1;
            long exp = rp != null && rp.GetMapValue("rp_exp") != null ? rp.GetMapValue("rp_exp").AsInt64(0) : 0;
            int fu = rp != null && rp.GetMapValue("rp_unlocked_furnace") != null ? rp.GetMapValue("rp_unlocked_furnace").AsInt32(1) : 1;
            var pli = MiscDatabase.PillLevels.FirstOrDefault(x => x.Level == lv);
            if (pli != null) cmbPillLevel.SelectedItem = pli;
            var fi = MiscDatabase.Furnaces.FirstOrDefault(x => x.Id == fu);
            if (fi != null) cmbFurnace.SelectedItem = fi;
            lblPillInfo.Text = string.Format("当前：{0} 级（经验 {1}），已解锁丹炉 {2} 个。", lv, exp, fu);
            RefreshForgeUI();
        }

        private void SetSelectedRepAndWrite()
        {
            if (currentSlot == null || lvRep.SelectedItems.Count == 0) { MessageBox.Show(this, "请先在列表里选一行。", "提示"); return; }
            var tag = (object[])lvRep.SelectedItems[0].Tag;
            string key = (string)tag[0]; int id = (int)tag[1];
            long v = (long)numRep.Value;
            string name = lvRep.SelectedItems[0].SubItems[1].Text;
            ReloadIfDiskChanged();
            if (key == "item")
            {
                if (!SetBagItemTotal(id, v)) return;
            }
            else
            {
                var bv = GetBehaviorValueNode();
                if (bv == null) { MessageBox.Show(this, "存档里没找到声望数据。", "错误"); return; }
                string field = key == "city" ? "city_reputes" : "sect_reputes";
                var map = bv.GetMapValue(field);
                if (map == null || map.Kind != MsgPackKind.Map) { map = MsgPackNode.CreateMap(); bv.SetMapValue(field, map); }
                var node = map.GetMapValueByInt(id);
                if (node != null) node.SetIntValue(v); else SetIntKeyValue(map, id, MsgPackNode.CreateInt(v));
            }
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已把【{0}】改为 {1:N0}，并写入 [{2}]。", name, v, currentSlot.SlotName);
        }

        // 把某种普通物品的总数设成 total（多删少补，只动普通格式的格子）
        private bool SetBagItemTotal(int itemId, long total)
        {
            ItemInfo info;
            if (!GameDatabase.Items.TryGetValue(itemId, out info)) return false;
            var items = GetBagItemsNode();
            var bag = GetBagNode();
            if (items == null || bag == null) { MessageBox.Show(this, "存档里没找到背包数据。", "错误"); return false; }
            var cells = new List<MsgPackNode>();
            foreach (var cell in items.ArrayItems)
            {
                if (cell.Kind != MsgPackKind.Array || cell.ArrayItems == null || cell.ArrayItems.Count < 2) continue;
                if (cell.ArrayItems[0].AsInt64(-1) != 0) continue;
                var m = cell.ArrayItems[1];
                var idn = m.Kind == MsgPackKind.Map ? m.GetMapValue("item_id") : null;
                if (idn != null && idn.AsInt32(0) == itemId) cells.Add(cell);
            }
            long remaining = total;
            foreach (var cell in cells)
            {
                var cnt = cell.ArrayItems[1].GetMapValue("count");
                long put = Math.Min(info.MaxPerGrid, remaining);
                if (put > 0) { if (cnt.AsInt64(-1) != put) cnt.SetIntValue(put); remaining -= put; }
                else
                {
                    int idx = items.ArrayItems.IndexOf(cell);
                    var nil = CreateNil(); nil.Parent = items;
                    items.ArrayItems[idx] = nil;
                    items.MarkModified();
                }
            }
            if (remaining > 0)
            {
                // 剩下的用添加逻辑（不弹确认，直接新开格子）
                AppendNewStacks(info, remaining, 1);
            }
            return true;
        }

        // 直接新开格子（不做确认/不补已有格子），供内部使用
        private void AppendNewStacks(ItemInfo info, long amount, int pillGrade)
        {
            var bag = GetBagNode();
            var items = GetBagItemsNode();
            bool oneEach = info.Format == 2 || info.Format == 4 || info.Format == 5;
            long max = oneEach ? 1 : info.MaxPerGrid;
            var nextUidNode = bag.GetMapValue("next_uid");
            long nextUid = nextUidNode != null ? nextUidNode.AsInt64(0) : 0;
            foreach (var cell in items.ArrayItems)
            {
                if (cell.Kind != MsgPackKind.Array || cell.ArrayItems == null || cell.ArrayItems.Count < 2) continue;
                var u = cell.ArrayItems[1].Kind == MsgPackKind.Map ? cell.ArrayItems[1].GetMapValue("uid") : null;
                if (u != null && u.AsInt64(0) >= nextUid) nextUid = u.AsInt64(0) + 1;
            }
            long nowMs = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            long remaining = amount;
            int guard = 0;
            while (remaining > 0 && guard++ < MaxNewStacksPerAdd)
            {
                long c = Math.Min(max, remaining);
                var m = MsgPackNode.CreateMap();
                AddFormatSpecificFields(m, info, pillGrade);
                m.SetMapValue("item_id", MsgPackNode.CreateInt(info.Id));
                m.SetMapValue("count", MsgPackNode.CreateInt(c));
                m.SetMapValue("is_new", MsgPackNode.CreateBool(true));
                m.SetMapValue("is_equipped", MsgPackNode.CreateBool(false));
                m.SetMapValue("timestamp_get", MsgPackNode.CreateInt(nowMs));
                m.SetMapValue("uid", MsgPackNode.CreateInt(nextUid));
                var cellNew = MsgPackNode.CreateArray(new List<MsgPackNode> { MsgPackNode.CreateInt(info.Format), m });
                cellNew.Parent = items;
                items.ArrayItems.Add(cellNew);
                nextUid++;
                remaining -= c;
            }
            items.MarkModified();
            if (nextUidNode != null) nextUidNode.SetIntValue(nextUid); else bag.SetMapValue("next_uid", MsgPackNode.CreateInt(nextUid));
        }

        private static readonly int[] FogRegionIds = { 20001, 20002, 20003, 20004 };

        private void RevealFogAndWrite()
        {
            if (currentSlot == null) return;
            ReloadIfDiskChanged();
            var pm = GetPlayerModelNode();
            if (pm == null) return;
            var fog = pm.GetMapValue("map_fog_seen_regions");
            if (fog == null || fog.Kind != MsgPackKind.Map) { fog = MsgPackNode.CreateMap(); pm.SetMapValue("map_fog_seen_regions", fog); }
            var seen = fog.GetMapValueByInt(200);
            if (seen == null || seen.Kind != MsgPackKind.Array) { seen = MsgPackNode.CreateArray(); SetIntKeyValue(fog, 200, seen); }
            var have = new HashSet<long>(seen.ArrayItems.Select(x => x.AsInt64(0)));
            int added = 0;
            foreach (var r in FogRegionIds)
                if (!have.Contains(r)) { var n = MsgPackNode.CreateInt(r); n.Parent = seen; seen.ArrayItems.Add(n); added++; }
            if (added == 0) { lblStatus.Text = "地图迷雾已经全部揭开了。"; return; }
            seen.MarkModified();
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已揭开 {0} 块地图迷雾，并写入 [{1}]。", added, currentSlot.SlotName);
        }

        private void SetPillLevelAndWrite()
        {
            if (currentSlot == null) return;
            var pl = cmbPillLevel.SelectedItem as PillLevelInfo;
            var fu = cmbFurnace.SelectedItem as FurnaceInfo;
            if (pl == null || fu == null) return;
            ReloadIfDiskChanged();
            var pm = GetPlayerModelNode();
            var rp = pm != null ? pm.GetMapValue("refining_pills") : null;
            if (rp == null || rp.Kind != MsgPackKind.Map) { MessageBox.Show(this, "存档里没找到炼丹数据。", "错误"); return; }
            var lvNode = rp.GetMapValue("rp_level");
            var expNode = rp.GetMapValue("rp_exp");
            int oldLv = lvNode != null ? lvNode.AsInt32(1) : 1;
            if (oldLv != pl.Level)
            {
                if (lvNode != null) lvNode.SetIntValue(pl.Level); else rp.SetMapValue("rp_level", MsgPackNode.CreateInt(pl.Level));
                if (expNode != null) expNode.SetIntValue(pl.Exp); else rp.SetMapValue("rp_exp", MsgPackNode.CreateInt(pl.Exp));
            }
            var fuNode = rp.GetMapValue("rp_unlocked_furnace");
            if (fuNode != null) fuNode.SetIntValue(fu.Id); else rp.SetMapValue("rp_unlocked_furnace", MsgPackNode.CreateInt(fu.Id));
            // 背包里补上缺的丹炉物品
            int addedFurnace = 0;
            foreach (var f in MiscDatabase.Furnaces.Where(x => x.Id <= fu.Id))
            {
                ItemInfo info;
                if (GetBagItemTotal(f.ItemId) == 0 && GameDatabase.Items.TryGetValue(f.ItemId, out info)) { AppendNewStacks(info, 1, 1); addedFurnace++; }
            }
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已把炼丹等级改为 {0}，已解锁丹炉 {1} 个{2}，并写入 [{3}]。", pl.Level, fu.Id,
                addedFurnace > 0 ? string.Format("（背包补了 {0} 个丹炉）", addedFurnace) : "", currentSlot.SlotName);
        }

        // ---------------- 功法 / 心法 直接学会 ----------------
        private ListView lvLearn;

        private void BuildLearnTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10) };
            var top = new Label
            {
                Dock = DockStyle.Top, Height = 40, ForeColor = Color.FromArgb(45, 75, 110),
                Text = "列出所有有秘籍的功法和心法（可按住 Ctrl / Shift 多选）。学心法时会和游戏一样：同时学会它的初始功法，并建好它的技能槽。\r\n比较稳妥的做法仍是在【背包物品】里加秘籍、进游戏使用。"
            };
            lvLearn = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = true };
            foreach (var col in new[] { "名称", "类型", "阶", "ID", "状态" }) lvLearn.Columns.Add(col, col == "名称" ? 160 : 80);
            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 46 };
            var btnLearn = new Button { Text = "学会选中的", Location = new Point(2, 8), Size = new Size(140, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnLearn.Click += (s, e) => LearnAndWrite(false);
            var btnAll = new Button { Text = "学会全部未学的", Location = new Point(150, 8), Size = new Size(140, 30) };
            btnAll.Click += (s, e) => LearnAndWrite(true);
            bottom.Controls.AddRange(new Control[] { btnLearn, btnAll });
            pnl.Controls.Add(lvLearn); pnl.Controls.Add(bottom); pnl.Controls.Add(top);
            tab.Controls.Add(pnl);
        }

        private HashSet<long> GetLearnedSkillIds()
        {
            var c = GetCombatNode();
            var ls = c != null ? c.GetMapValue("learned_skills") : null;
            var set = new HashSet<long>();
            if (ls != null && ls.Kind == MsgPackKind.Map) foreach (var kv in ls.MapEntries) set.Add(kv.Key.AsInt64(0));
            return set;
        }

        private HashSet<long> GetLearnedPassiveIds()
        {
            var c = GetCombatNode();
            var lp = c != null ? c.GetMapValue("learned_core_passives") : null;
            var set = new HashSet<long>();
            if (lp != null && lp.Kind == MsgPackKind.Array) foreach (var x in lp.ArrayItems) set.Add(x.AsInt64(0));
            return set;
        }

        private void RefreshLearnTab()
        {
            if (lvLearn == null) return;
            var ls = GetLearnedSkillIds(); var lp = GetLearnedPassiveIds();
            lvLearn.BeginUpdate();
            lvLearn.Items.Clear();
            foreach (var p in MiscDatabase.Passives.Values.Where(x => x.BookItemId > 0).OrderBy(x => x.Tier).ThenBy(x => x.Id))
            {
                bool has = lp.Contains(p.Id);
                var lvi = new ListViewItem(p.Name) { Tag = "p:" + p.Id };
                lvi.SubItems.Add("心法"); lvi.SubItems.Add(p.Tier.ToString()); lvi.SubItems.Add(p.Id.ToString()); lvi.SubItems.Add(has ? "已学" : "未学");
                if (has) lvi.ForeColor = Color.Gray;
                lvLearn.Items.Add(lvi);
            }
            foreach (var s in MiscDatabase.Skills.Values.Where(x => x.BookItemId > 0).OrderBy(x => x.Tier).ThenBy(x => x.Id))
            {
                bool has = ls.Contains(s.Id);
                var lvi = new ListViewItem(s.Name) { Tag = "s:" + s.Id };
                lvi.SubItems.Add("功法"); lvi.SubItems.Add(s.Tier.ToString()); lvi.SubItems.Add(s.Id.ToString()); lvi.SubItems.Add(has ? "已学" : "未学");
                if (has) lvi.ForeColor = Color.Gray;
                lvLearn.Items.Add(lvi);
            }
            lvLearn.EndUpdate();
        }

        private void LearnAndWrite(bool all)
        {
            if (currentSlot == null) return;
            var targets = new List<string>();
            foreach (ListViewItem it in (all ? lvLearn.Items.Cast<ListViewItem>() : lvLearn.SelectedItems.Cast<ListViewItem>()))
                if (it.SubItems[4].Text == "未学") targets.Add((string)it.Tag);
            if (targets.Count == 0) { MessageBox.Show(this, all ? "已经全部学会了。" : "请先选中未学的功法/心法。", "提示"); return; }
            if (all && MessageBox.Show(this, string.Format("确定要一次学会 {0} 门功法/心法吗？", targets.Count), "确认", MessageBoxButtons.YesNo) != DialogResult.Yes) return;

            ReloadIfDiskChanged();
            var c = GetCombatNode();
            if (c == null) return;
            var ls = c.GetMapValue("learned_skills");
            var lp = c.GetMapValue("learned_core_passives");
            var cfgs = c.GetMapValue("core_passive_skill_configs");
            if (ls == null || ls.Kind != MsgPackKind.Map || lp == null || lp.Kind != MsgPackKind.Array || cfgs == null || cfgs.Kind != MsgPackKind.Map)
            {
                MessageBox.Show(this, "存档里没找到功法数据。", "错误");
                return;
            }
            int nSkill = 0, nPassive = 0;
            Action<int> learnSkill = sid =>
            {
                if (ls.GetMapValueByInt(sid) == null) { SetIntKeyValue(ls, sid, MsgPackNode.CreateInt(1)); nSkill++; }
            };
            foreach (var t in targets)
            {
                int id = int.Parse(t.Substring(2));
                if (t[0] == 's') { learnSkill(id); continue; }
                PassiveInfo p;
                if (!MiscDatabase.Passives.TryGetValue(id, out p)) continue;
                if (!lp.ArrayItems.Any(x => x.AsInt64(0) == id))
                {
                    var n = MsgPackNode.CreateInt(id); n.Parent = lp; lp.ArrayItems.Add(n); lp.MarkModified(); nPassive++;
                }
                foreach (var sid in p.InitSkills) learnSkill(sid);
                if (cfgs.GetMapValueByInt(id) == null)
                {
                    // 和游戏新学心法时一样：4 个槽（或配置的槽数），前面放初始功法，其余为空
                    int slots = p.SlotCount > 0 ? p.SlotCount : 4;
                    var cfg = MsgPackNode.CreateMap();
                    for (int i = 0; i < slots; i++)
                    {
                        int sid = i < p.InitSkills.Count ? p.InitSkills[i] : 0;
                        SkillInfo si;
                        int kind = sid > 0 ? (MiscDatabase.Skills.TryGetValue(sid, out si) ? si.AbilityKind : 2) : 0;
                        var slot = MsgPackNode.CreateMap();
                        slot.SetMapValue("slot_index", MsgPackNode.CreateInt(i));
                        slot.SetMapValue("skill_id", MsgPackNode.CreateInt(sid));
                        slot.SetMapValue("skill_level", MsgPackNode.CreateInt(sid > 0 ? 1 : 0));
                        slot.SetMapValue("ability_kind", MsgPackNode.CreateInt(kind));
                        SetIntKeyValue(cfg, i, slot);
                    }
                    SetIntKeyValue(cfgs, id, cfg);
                }
            }
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 新学会心法 {0} 门、功法 {1} 门，并写入 [{2}]。", nPassive, nSkill, currentSlot.SlotName);
        }

        // ---------------- 删除背包物品 ----------------
        private void DeleteSelectedBagStack()
        {
            if (currentSlot == null || lvBag.SelectedItems.Count == 0) { MessageBox.Show(this, "请先在左边背包列表里选一格物品。", "提示"); return; }
            var tag = (long[])lvBag.SelectedItems[0].Tag;
            long uid = tag[0];
            string name = lvBag.SelectedItems[0].Text;
            ReloadIfDiskChanged();
            var cell = FindBagStackByUid(uid);
            if (cell == null) { MessageBox.Show(this, "在最新的存档里找不到这一格物品了，请刷新后再试。", "提示"); RefreshBagListView(); return; }
            var m = cell.ArrayItems[1];
            if (m.GetMapValue("is_equipped") != null && m.GetMapValue("is_equipped").AsBool(false))
            {
                MessageBox.Show(this, "这件物品正在装备中，请先在游戏里卸下再删除。", "提示");
                return;
            }
            long cnt = m.GetMapValue("count") != null ? m.GetMapValue("count").AsInt64(0) : 0;
            if (MessageBox.Show(this, string.Format("确定要删除这一格【{0}】×{1:N0} 吗？\n（写入前会自动备份）", name, cnt), "确认删除", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            var items = GetBagItemsNode();
            int idx = items.ArrayItems.IndexOf(cell);
            var nil = CreateNil(); nil.Parent = items;
            items.ArrayItems[idx] = nil;   // 游戏删除物品时也是把这一格变成空(nil)
            items.MarkModified();
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshDaoTabUI();
            lblStatus.Text = string.Format("✅ 已删除【{0}】×{1:N0}，并写入 [{2}]。", name, cnt, currentSlot.SlotName);
        }

        // ---------------- NPC 境界 / 寿元 ----------------
        private ComboBox cmbNpcLayer;
        private NumericUpDown numNpcLifespan;

        private void LoadNpcRealmControls(int npcId)
        {
            if (cmbNpcLayer == null) return;
            MsgPackNode npc;
            bool inSave = saveNpcMap.TryGetValue(npcId, out npc);
            cmbNpcLayer.Enabled = numNpcLifespan.Enabled = inSave;
            if (!inSave) return;
            var cs = npc.GetMapValue("cultivation_state");
            int layer = cs != null && cs.GetMapValue("cultivate_layer_id") != null ? cs.GetMapValue("cultivate_layer_id").AsInt32(0) : 0;
            var li = MiscDatabase.Layers.FirstOrDefault(x => x.Id == layer);
            cmbNpcLayer.SelectedItem = li;
            var lb = npc.GetMapValue("lifespan_bonus");
            numNpcLifespan.Value = Math.Max(numNpcLifespan.Minimum, Math.Min(numNpcLifespan.Maximum, lb != null ? lb.AsInt64(0) : 0));
        }

        private void SetNpcRealmAndWrite()
        {
            if (currentSlot == null || selectedNpcId <= 0) return;
            var li = cmbNpcLayer.SelectedItem as LayerInfo;
            if (li == null) { MessageBox.Show(this, "请选择境界。", "提示"); return; }
            long lifespan = (long)numNpcLifespan.Value;
            ReloadIfDiskChanged();
            MsgPackNode npc;
            if (!saveNpcMap.TryGetValue(selectedNpcId, out npc)) { MessageBox.Show(this, "该 NPC 不在存档里。", "提示"); return; }
            var cs = npc.GetMapValue("cultivation_state");
            if (cs == null || cs.Kind != MsgPackKind.Map) { MessageBox.Show(this, "这个 NPC 没有修为数据。", "提示"); return; }
            var ln = cs.GetMapValue("cultivate_layer_id");
            if (ln == null || ln.AsInt32(0) != li.Id)
            {
                if (ln != null) ln.SetIntValue(li.Id); else cs.SetMapValue("cultivate_layer_id", MsgPackNode.CreateInt(li.Id));
                var ex = cs.GetMapValue("cultivate_exp");
                if (ex != null) ex.SetIntValue(0);   // 换层后当前层经验从 0 开始
            }
            var lb = npc.GetMapValue("lifespan_bonus");
            if (lb != null) { if (lb.AsInt64(long.MinValue) != lifespan) lb.SetIntValue(lifespan); }
            else npc.SetMapValue("lifespan_bonus", MsgPackNode.CreateInt(lifespan));
            if (!WriteCurrentSaveImmediately(false)) return;
            NpcConfigInfo cfg; GameDatabase.Npcs.TryGetValue(selectedNpcId, out cfg);
            lblStatus.Text = string.Format("✅ 已把【{0}】的境界改为 {1}、寿元加成 {2}，并写入 [{3}]。", cfg != null ? cfg.Name : selectedNpcId.ToString(), li.Name, lifespan, currentSlot.SlotName);
        }

        // ---------------- 法宝：改品阶 / 加词条槽 ----------------
        private ComboBox cmbArtTier;

        private void SetArtifactTierAndWrite()
        {
            if (currentSlot == null || selectedArtifactUid < 0) { MessageBox.Show(this, "请先在左边选一件法宝。", "提示"); return; }
            int tier = cmbArtTier.SelectedIndex + 1;
            if (tier < 1) return;
            long uid = selectedArtifactUid;
            ReloadIfDiskChanged();
            var m = FindArtifactByUid(uid);
            if (m == null) return;
            if (m.GetMapValue("alchemy_crafted") == null || !m.GetMapValue("alchemy_crafted").AsBool(false))
            {
                MessageBox.Show(this, "未炼制的法宝没有品阶。", "提示"); return;
            }
            int proto = m.GetMapValue("alchemy_proto_item_id") != null ? m.GetMapValue("alchemy_proto_item_id").AsInt32(0) : 0;
            List<ProtoTier> tiers;
            if (!MiscDatabase.Protos.TryGetValue(proto, out tiers)) { MessageBox.Show(this, "找不到这件法宝的炼制原型数据。", "错误"); return; }
            var pt = tiers.FirstOrDefault(x => x.Tier == tier);
            if (pt == null) { MessageBox.Show(this, "这件法宝没有这个品阶。", "提示"); return; }
            m.SetMapValue("alchemy_tier_id", MsgPackNode.CreateInt(tier));
            var score = m.GetMapValue("alchemy_score");
            long oldScore = score != null ? score.AsInt64(0) : 0;
            long nextMin = tiers.Where(x => x.Tier == tier + 1).Select(x => x.ScoreMin).DefaultIfEmpty(long.MaxValue).First();
            // 评分：已经落在这个品阶区间就不动，否则设为该品阶最低分
            long newScore = (oldScore >= pt.ScoreMin && oldScore < nextMin) ? oldScore : pt.ScoreMin;
            m.SetMapValue("alchemy_score", MsgPackNode.CreateInt(newScore));
            var attrs = new List<MsgPackNode>();
            foreach (var a in pt.Attrs)
                attrs.Add(MsgPackNode.CreateArray(new List<MsgPackNode> { MsgPackNode.CreateInt(a.Key), MsgPackNode.CreateInt((long)Math.Round(a.Value)) }));
            m.SetMapValue("alchemy_attrs", MsgPackNode.CreateArray(attrs));
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshArtifactList();
            SelectArtifact(uid);
            lblStatus.Text = string.Format("✅ 已把法宝改为 {0}（主属性按炼制原型重设，评分 {1}），并写入 [{2}]。", TierNames[tier], newScore, currentSlot.SlotName);
        }

        private void AddArtifactAffixSlotAndWrite()
        {
            if (currentSlot == null || selectedArtifactUid < 0) { MessageBox.Show(this, "请先在左边选一件法宝。", "提示"); return; }
            long uid = selectedArtifactUid;
            ReloadIfDiskChanged();
            var m = FindArtifactByUid(uid);
            if (m == null) return;
            if (m.GetMapValue("alchemy_crafted") == null || !m.GetMapValue("alchemy_crafted").AsBool(false))
            {
                MessageBox.Show(this, "未炼制的法宝不能加词条。", "提示"); return;
            }
            var affixes = m.GetMapValue("alchemy_affixes");
            if (affixes == null || affixes.Kind != MsgPackKind.Array) { affixes = MsgPackNode.CreateArray(); m.SetMapValue("alchemy_affixes", affixes); }
            var existing = affixes.ArrayItems.Where(x => x.Kind == MsgPackKind.Map).ToList();
            if (existing.Count >= 3) { MessageBox.Show(this, "法宝最多 3 条词条（游戏里没见过超过 3 条的）。", "提示"); return; }
            int nextSlot = existing.Count == 0 ? 0 : existing.Max(x => x.GetMapValue("slot_index") != null ? x.GetMapValue("slot_index").AsInt32(0) : 0) + 1;
            // 默认用这件法宝第一条词条的同一种（没有就用筑基·紫·暴击率），数值取该词条最小值，之后可以在上面改
            int cid = existing.Count > 0 && existing[0].GetMapValue("config_id") != null ? existing[0].GetMapValue("config_id").AsInt32(20023) : 20023;
            AffixInfo a;
            double val = GameDatabase.Affixes.TryGetValue(cid, out a) ? a.Min : 5;
            var af = MsgPackNode.CreateMap();
            af.SetMapValue("slot_index", MsgPackNode.CreateInt(nextSlot));
            af.SetMapValue("config_id", MsgPackNode.CreateInt(cid));
            af.SetMapValue("value", MsgPackNode.CreateFloat((float)val));
            af.Parent = affixes;
            affixes.ArrayItems.Add(af);
            affixes.MarkModified();
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshArtifactList();
            SelectArtifact(uid);
            lblStatus.Text = string.Format("✅ 已给法宝加了第 {0} 条词条（先用默认词条，可以在上面改成想要的再写入），并写入 [{1}]。", existing.Count + 1, currentSlot.SlotName);
        }

        // =========================================================================
        // 8.8 关系页：游戏里三种关系是分开的
        //   道侣 / 结缘：npc_relation.dao_companion_npc_ids，主道侣 = dao_companion_npc_id
        //   同道：npc_dao_ally.npc_ids（人数上限按玩家境界：炼气3 / 筑基5 / 结丹10 / 元婴15 / 化神20）
        //         解除同道后有冷却：npc_dao_ally.release_cooldown_until_units
        //   同道助战：npc_dao_ally.assist_counts / assist_months（只是助战记录）
        //   师父 master_npc_id / 徒弟 disciple_npc_ids / 好友 friend_npc_ids
        //   洞府（小重天·仙居楼）：npc_housing.residents {房间序号0-4: NPC}
        // =========================================================================
        private TabControl mainTabs;
        private TabPage npcTabPage;
        private ListView lvCompanions;
        private ComboBox cmbRelFilter;
        private NumericUpDown numCompIntimacy;
        private Label lblCompSummary;
        private ComboBox cmbHouseRoom;
        private static readonly string[] HouseRoomNames = { "隐月楼", "映雪阁", "听雨楼", "栖霞院", "采薇居" };

        private Button MkBtn(string text, int x, int y, int w, bool primary = false)
        {
            var b = new Button { Text = text, Location = new Point(x, y), Size = new Size(w, 30) };
            if (primary) { b.BackColor = ThemeGreen; b.ForeColor = Color.White; b.FlatStyle = FlatStyle.Flat; }
            return b;
        }

        private void BuildCompanionTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10) };
            var top = new Panel { Dock = DockStyle.Top, Height = 36 };
            var lblF = new Label { Text = "显示：", Location = new Point(2, 9), AutoSize = true };
            cmbRelFilter = new ComboBox { Location = new Point(48, 5), Width = 150, DropDownStyle = ComboBoxStyle.DropDownList };
            cmbRelFilter.Items.AddRange(new object[] { "同道", "道侣（结缘）", "洞府住客", "师徒", "好友", "全部有关系的人", "可结同道的人（好感≥100）" });
            cmbRelFilter.SelectedIndex = 0;
            cmbRelFilter.SelectedIndexChanged += (s, e) => RefreshCompanionList();
            lblCompSummary = new Label { Location = new Point(212, 9), AutoSize = true, ForeColor = Color.FromArgb(45, 75, 110), Font = new Font(Font, FontStyle.Bold) };
            top.Controls.AddRange(new Control[] { lblF, cmbRelFilter, lblCompSummary });

            lvCompanions = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = false };
            foreach (var c in new[] { new { t = "姓名", w = 80 }, new { t = "称号", w = 100 }, new { t = "关系", w = 230 }, new { t = "好感", w = 50 }, new { t = "境界", w = 105 }, new { t = "当前天赋（✔=已解锁）", w = 360 }, new { t = "ID", w = 70 } })
                lvCompanions.Columns.Add(c.t, c.w);
            lvCompanions.SelectedIndexChanged += (s, e) =>
            {
                if (lvCompanions.SelectedItems.Count == 0) return;
                numCompIntimacy.Value = Math.Max(numCompIntimacy.Minimum, Math.Min(numCompIntimacy.Maximum, GetNpcSaveIntimacy((int)lvCompanions.SelectedItems[0].Tag)));
            };
            lvCompanions.DoubleClick += (s, e) => JumpToNpcEditor();

            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 150 };
            // 第一行：好感 / 编辑
            var lblI = new Label { Text = "好感度：", Location = new Point(2, 12), AutoSize = true };
            numCompIntimacy = new NumericUpDown { Location = new Point(60, 8), Width = 80, Minimum = -9999, Maximum = MaxIntimacy };
            var b1 = MkBtn("写入好感", 148, 5, 90, true); b1.Click += (s, e) => SetCompanionIntimacyAndWrite();
            var b2 = MkBtn("满好感(500)", 244, 5, 100); b2.Click += (s, e) => numCompIntimacy.Value = MaxIntimacy;
            var b3 = MkBtn("去编辑天赋 / 境界（也可双击）", 352, 5, 230, true); b3.BackColor = Color.FromArgb(35, 95, 165); b3.Click += (s, e) => JumpToNpcEditor();
            // 第二行：同道 / 道侣
            var lblR = new Label { Text = "关系：", Location = new Point(2, 50), AutoSize = true, Font = new Font(Font, FontStyle.Bold) };
            var b4 = MkBtn("结为同道", 60, 43, 90); b4.Click += (s, e) => SetDaoAllyAndWrite(true);
            var b5 = MkBtn("解除同道", 156, 43, 90); b5.Click += (s, e) => SetDaoAllyAndWrite(false);
            var b6 = MkBtn("结缘（加为道侣）", 264, 43, 130); b6.Click += (s, e) => SetDaoCompanionAndWrite(true);
            var b7 = MkBtn("解除结缘", 400, 43, 90); b7.Click += (s, e) => SetDaoCompanionAndWrite(false);
            var b8 = MkBtn("设为主道侣", 496, 43, 100); b8.Click += (s, e) => SetMainCompanionAndWrite();
            // 第三行：洞府
            var lblH = new Label { Text = "洞府：", Location = new Point(2, 88), AutoSize = true, Font = new Font(Font, FontStyle.Bold) };
            cmbHouseRoom = new ComboBox { Location = new Point(60, 84), Width = 210, DropDownStyle = ComboBoxStyle.DropDownList };
            var b9 = MkBtn("入住这个房间", 278, 81, 110); b9.Click += (s, e) => SetHousingAndWrite(true);
            var b10 = MkBtn("请离洞府", 394, 81, 90); b10.Click += (s, e) => SetHousingAndWrite(false);
            // 第四行：批量
            var lblB = new Label { Text = "批量：", Location = new Point(2, 126), AutoSize = true, Font = new Font(Font, FontStyle.Bold) };
            var b11 = MkBtn("当前列表全部满好感", 60, 119, 160); b11.Click += (s, e) => BatchAndWrite(true, false);
            var b12 = MkBtn("当前列表全部天赋槽解锁", 226, 119, 180); b12.Click += (s, e) => BatchAndWrite(false, true);
            var lblBn = new Label { Text = "（只作用于上面列表里显示的人；解锁只改\"是否解锁\"，不换天赋）", Location = new Point(414, 126), AutoSize = true, ForeColor = Color.FromArgb(120, 90, 40) };
            bottom.Controls.AddRange(new Control[] { lblI, numCompIntimacy, b1, b2, b3, lblR, b4, b5, b6, b7, b8, lblH, cmbHouseRoom, b9, b10, lblB, b11, b12, lblBn });

            pnl.Controls.Add(lvCompanions);
            pnl.Controls.Add(bottom);
            pnl.Controls.Add(top);
            tab.Controls.Add(pnl);
        }

        private MsgPackNode GetRelationNode()
        {
            var pm = GetPlayerModelNode();
            var r = pm != null ? pm.GetMapValue("npc_relation") : null;
            return (r != null && r.Kind == MsgPackKind.Map) ? r : null;
        }

        private MsgPackNode GetDaoAllyNode()
        {
            var pm = GetPlayerModelNode();
            var r = pm != null ? pm.GetMapValue("npc_dao_ally") : null;
            return (r != null && r.Kind == MsgPackKind.Map) ? r : null;
        }

        private MsgPackNode GetHousingResidents(bool create)
        {
            var pm = GetPlayerModelNode();
            var h = pm != null ? pm.GetMapValue("npc_housing") : null;
            if (h == null || h.Kind != MsgPackKind.Map) return null;
            var r = h.GetMapValue("residents");
            if ((r == null || r.Kind != MsgPackKind.Map) && create) { r = MsgPackNode.CreateMap(); h.SetMapValue("residents", r); }
            return (r != null && r.Kind == MsgPackKind.Map) ? r : null;
        }

        private static List<long> ReadIdList(MsgPackNode n)
        {
            var list = new List<long>();
            if (n != null && n.Kind == MsgPackKind.Array && n.ArrayItems != null)
                foreach (var x in n.ArrayItems) list.Add(x.AsInt64(0));
            return list;
        }

        // 玩家当前境界（1 炼气 … 5 化神）
        private int GetPlayerRealm()
        {
            var c = GetCombatNode();
            var ln = c != null ? c.GetMapValue("cultivate_layer_id") : null;
            var li = ln != null ? MiscDatabase.Layers.FirstOrDefault(x => x.Id == ln.AsInt64(0)) : null;
            return li != null ? li.Realm : 0;
        }

        private int GetNpcRealm(int nid)
        {
            MsgPackNode npc;
            if (!saveNpcMap.TryGetValue(nid, out npc)) return 0;
            var cs = npc.GetMapValue("cultivation_state");
            var ln = cs != null ? cs.GetMapValue("cultivate_layer_id") : null;
            var li = ln != null ? MiscDatabase.Layers.FirstOrDefault(x => x.Id == ln.AsInt64(0)) : null;
            return li != null ? li.Realm : 0;
        }

        private int GetDaoAllyCapacity()
        {
            int realm = GetPlayerRealm();
            RealmInfo ri;
            return MiscDatabase.Realms.TryGetValue(realm, out ri) ? ri.AllyCapacity : 0;
        }

        private void RefreshCompanionList()
        {
            if (lvCompanions == null) return;
            int keep = lvCompanions.SelectedItems.Count > 0 ? (int)lvCompanions.SelectedItems[0].Tag : -1;
            var rel = GetRelationNode();
            var allyNode = GetDaoAllyNode();
            long main = rel != null && rel.GetMapValue("dao_companion_npc_id") != null ? rel.GetMapValue("dao_companion_npc_id").AsInt64(0) : 0;
            long master = rel != null && rel.GetMapValue("master_npc_id") != null ? rel.GetMapValue("master_npc_id").AsInt64(0) : 0;
            var spouses = ReadIdList(rel != null ? rel.GetMapValue("dao_companion_npc_ids") : null);
            var disciples = ReadIdList(rel != null ? rel.GetMapValue("disciple_npc_ids") : null);
            var friends = ReadIdList(rel != null ? rel.GetMapValue("friend_npc_ids") : null);
            var allies = ReadIdList(allyNode != null ? allyNode.GetMapValue("npc_ids") : null);
            var assists = allyNode != null ? allyNode.GetMapValue("assist_counts") : null;
            var housing = new Dictionary<long, int>();
            var res = GetHousingResidents(false);
            if (res != null) foreach (var kv in res.MapEntries) housing[kv.Value.AsInt64(0)] = kv.Key.AsInt32(0);

            string filter = cmbRelFilter.SelectedItem as string ?? "同道";
            IEnumerable<long> ids;
            switch (filter)
            {
                case "道侣（结缘）": ids = (main > 0 && !spouses.Contains(main) ? new List<long> { main } : new List<long>()).Concat(spouses); break;
                case "洞府住客": ids = housing.OrderBy(x => x.Value).Select(x => x.Key); break;
                case "师徒": ids = (master > 0 ? new List<long> { master } : new List<long>()).Concat(disciples); break;
                case "好友": ids = friends; break;
                case "全部有关系的人": ids = allies.Concat(spouses).Concat(housing.Keys).Concat(disciples).Concat(friends).Concat(master > 0 ? new[] { master } : new long[0]).Distinct(); break;
                case "可结同道的人（好感≥100）": ids = saveNpcMap.Keys.Where(id => GetNpcSaveIntimacy(id) >= 100 && !allies.Contains(id)).Select(id => (long)id).OrderByDescending(id => GetNpcSaveIntimacy((int)id)); break;
                default: ids = allies; break;
            }

            lvCompanions.BeginUpdate();
            lvCompanions.Items.Clear();
            foreach (var id in ids)
            {
                int nid = (int)id;
                NpcConfigInfo cfg; GameDatabase.Npcs.TryGetValue(nid, out cfg);
                var tags = new List<string>();
                if (allies.Contains(id)) tags.Add("同道");
                if (id == main) tags.Add("★主道侣");
                else if (spouses.Contains(id)) tags.Add("道侣");
                var ac = assists != null ? assists.GetMapValueByInt(id) : null;
                if (ac != null && ac.AsInt64(0) > 0) tags.Add("助战" + ac.AsInt64(0) + "次");
                int room;
                if (housing.TryGetValue(id, out room)) tags.Add("洞府·" + (room >= 0 && room < HouseRoomNames.Length ? HouseRoomNames[room] : ("房" + (room + 1))));
                if (id == master) tags.Add("师父");
                if (disciples.Contains(id)) tags.Add("徒弟");
                if (friends.Contains(id)) tags.Add("好友");

                string realm = "—";
                MsgPackNode npc;
                if (saveNpcMap.TryGetValue(nid, out npc))
                {
                    var cs = npc.GetMapValue("cultivation_state");
                    var ln = cs != null ? cs.GetMapValue("cultivate_layer_id") : null;
                    if (ln != null) realm = MiscDatabase.LayerName(ln.AsInt64(0));
                }
                var lvi = new ListViewItem(cfg != null ? cfg.Name : ("NPC" + nid)) { Tag = nid };
                lvi.SubItems.Add(cfg != null && !string.IsNullOrEmpty(cfg.Title) ? cfg.Title : "—");
                lvi.SubItems.Add(tags.Count > 0 ? string.Join(" · ", tags) : "—");
                lvi.SubItems.Add(saveNpcMap.ContainsKey(nid) ? GetNpcSaveIntimacy(nid).ToString() : "—");
                lvi.SubItems.Add(realm);
                lvi.SubItems.Add(GetNpcSaveTalentsSummary(nid));
                lvi.SubItems.Add(nid.ToString());
                if (allies.Contains(id)) lvi.Font = new Font(lvCompanions.Font, FontStyle.Bold);
                lvCompanions.Items.Add(lvi);
                if (nid == keep) lvi.Selected = true;
            }
            lvCompanions.EndUpdate();

            // 洞府房间下拉框
            int keepRoom = cmbHouseRoom.SelectedIndex;
            cmbHouseRoom.Items.Clear();
            for (int r = 0; r < HouseRoomNames.Length; r++)
            {
                long who = housing.Where(x => x.Value == r).Select(x => x.Key).FirstOrDefault();
                NpcConfigInfo wc; GameDatabase.Npcs.TryGetValue((int)who, out wc);
                cmbHouseRoom.Items.Add(string.Format("{0}　{1}", HouseRoomNames[r], who > 0 ? "（" + (wc != null ? wc.Name : who.ToString()) + "）" : "（空）"));
            }
            cmbHouseRoom.SelectedIndex = keepRoom >= 0 && keepRoom < cmbHouseRoom.Items.Count ? keepRoom : 0;

            NpcConfigInfo mc; GameDatabase.Npcs.TryGetValue((int)main, out mc);
            NpcConfigInfo ms; GameDatabase.Npcs.TryGetValue((int)master, out ms);
            int cap = GetDaoAllyCapacity();
            lblCompSummary.Text = string.Format("同道 {0}/{1}　|　道侣 {2} 人（主道侣：{3}）　|　洞府 {4}/5　|　师父：{5}　|　徒弟 {6} 人",
                allies.Count, cap > 0 ? cap.ToString() : "?", spouses.Count, mc != null ? mc.Name : "无", housing.Count, ms != null ? ms.Name : "无", disciples.Count);
        }

        private int SelectedCompanionId()
        {
            if (lvCompanions.SelectedItems.Count == 0) { MessageBox.Show(this, "请先在列表里选一个人。", "提示"); return -1; }
            return (int)lvCompanions.SelectedItems[0].Tag;
        }

        private string NpcName(int nid)
        {
            NpcConfigInfo c; return GameDatabase.Npcs.TryGetValue(nid, out c) ? c.Name : nid.ToString();
        }

        private void AfterRelationWrite(string msg)
        {
            RefreshNpcListView();
            RefreshCompanionList();
            lblStatus.Text = msg + string.Format("，并写入 [{0}]。", currentSlot.SlotName);
        }

        private void SetCompanionIntimacyAndWrite()
        {
            if (currentSlot == null) return;
            int nid = SelectedCompanionId(); if (nid < 0) return;
            int v = (int)numCompIntimacy.Value;
            ReloadIfDiskChanged();
            MsgPackNode npc;
            if (!saveNpcMap.TryGetValue(nid, out npc)) { MessageBox.Show(this, "这个人不在当前存档里。", "提示"); return; }
            var node = npc.GetMapValue("intimacy");
            if (node != null) node.SetIntValue(v); else npc.SetMapValue("intimacy", MsgPackNode.CreateInt(v));
            if (!WriteCurrentSaveImmediately(false)) return;
            AfterRelationWrite(string.Format("✅ 已把【{0}】的好感改为 {1}", NpcName(nid), v));
        }

        private void SetDaoAllyAndWrite(bool add)
        {
            if (currentSlot == null) return;
            int nid = SelectedCompanionId(); if (nid < 0) return;
            string name = NpcName(nid);
            ReloadIfDiskChanged();
            var ally = GetDaoAllyNode();
            if (ally == null) { MessageBox.Show(this, "存档里没找到同道数据（可能还没开启同道系统）。", "提示"); return; }
            var list = ally.GetMapValue("npc_ids");
            if (list == null || list.Kind != MsgPackKind.Array) { list = MsgPackNode.CreateArray(); ally.SetMapValue("npc_ids", list); }
            var ids = ReadIdList(list);
            if (add)
            {
                if (ids.Contains(nid)) { lblStatus.Text = name + " 已经是同道了。"; return; }
                if (!saveNpcMap.ContainsKey(nid)) { MessageBox.Show(this, "这个人不在当前存档里，不能结为同道。", "提示"); return; }
                int cap = GetDaoAllyCapacity();
                if (cap > 0 && ids.Count >= cap)
                {
                    MessageBox.Show(this, string.Format("同道人数已达上限（{0}/{1}）。\n游戏规则：炼气 3、筑基 5、结丹 10、元婴 15、化神 20。\n请先解除一位同道。", ids.Count, cap), "同道已满");
                    return;
                }
                var warn = new List<string>();
                int pr = GetPlayerRealm(), nr = GetNpcRealm(nid);
                if (pr > 0 && nr > pr) warn.Add("对方境界高于你（游戏里不允许）");
                if (GetNpcSaveIntimacy(nid) < 100) warn.Add("好感不足 100（游戏里会提示好感不足）");
                if (warn.Count > 0 && MessageBox.Show(this, string.Format("【{0}】在游戏里本来不能结为同道：\n• {1}\n\n仍要强行写入吗？", name, string.Join("\n• ", warn)), "提醒", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                var n = MsgPackNode.CreateInt(nid); n.Parent = list; list.ArrayItems.Add(n); list.MarkModified();
                // 清掉这个人的"解除同道冷却"
                var cd = ally.GetMapValue("release_cooldown_until_units");
                if (cd != null && cd.Kind == MsgPackKind.Map && cd.MapEntries.RemoveAll(kv => kv.Key.AsInt64(0) == nid) > 0) cd.MarkModified();
                if (!WriteCurrentSaveImmediately(false)) return;
                AfterRelationWrite(string.Format("✅ 已和【{0}】结为同道（{1}/{2}）", name, ids.Count + 1, cap));
            }
            else
            {
                if (!ids.Contains(nid)) { lblStatus.Text = name + " 不是同道。"; return; }
                if (MessageBox.Show(this, string.Format("确定和【{0}】解除同道吗？\n（游戏里解除会有一段时间不能再结同道；用编辑器解除不会加冷却）", name), "确认", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                list.ArrayItems.RemoveAll(x => x.AsInt64(0) == nid); list.MarkModified();
                if (!WriteCurrentSaveImmediately(false)) return;
                AfterRelationWrite(string.Format("✅ 已和【{0}】解除同道", name));
            }
        }

        private void SetDaoCompanionAndWrite(bool add)
        {
            if (currentSlot == null) return;
            int nid = SelectedCompanionId(); if (nid < 0) return;
            string name = NpcName(nid);
            NpcConfigInfo cfg; GameDatabase.Npcs.TryGetValue(nid, out cfg);
            ReloadIfDiskChanged();
            var rel = GetRelationNode();
            if (rel == null) { MessageBox.Show(this, "存档里没找到关系数据。", "错误"); return; }
            var list = rel.GetMapValue("dao_companion_npc_ids");
            if (list == null || list.Kind != MsgPackKind.Array) { list = MsgPackNode.CreateArray(); rel.SetMapValue("dao_companion_npc_ids", list); }
            var ids = ReadIdList(list);
            if (add)
            {
                if (ids.Contains(nid)) { lblStatus.Text = name + " 已经是道侣了。"; return; }
                if (MessageBox.Show(this, string.Format("确定和【{0}】结缘（加为道侣）吗？\n\n注意：游戏里结缘会播放结缘剧情、留下结缘影像等。用编辑器直接加只会改关系名单，没有这些剧情和影像{1}。",
                        name, cfg != null && !cfg.CanBeDaoCompanion ? "；而且游戏设定里这个人不能结缘" : ""), "确认结缘", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                var n = MsgPackNode.CreateInt(nid); n.Parent = list; list.ArrayItems.Add(n); list.MarkModified();
                var mn = rel.GetMapValue("dao_companion_npc_id");
                if (mn == null || mn.AsInt64(0) <= 0) rel.SetMapValue("dao_companion_npc_id", MsgPackNode.CreateInt(nid));
                if (!WriteCurrentSaveImmediately(false)) return;
                AfterRelationWrite(string.Format("✅ 已和【{0}】结缘", name));
            }
            else
            {
                if (!ids.Contains(nid)) { lblStatus.Text = name + " 不是道侣。"; return; }
                if (MessageBox.Show(this, string.Format("确定和【{0}】解除结缘吗？\n（只改关系名单；已有的结缘影像、双修记录不会删除）", name), "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                list.ArrayItems.RemoveAll(x => x.AsInt64(0) == nid); list.MarkModified();
                var mn = rel.GetMapValue("dao_companion_npc_id");
                if (mn != null && mn.AsInt64(0) == nid)
                {
                    long next = list.ArrayItems.Count > 0 ? list.ArrayItems[0].AsInt64(0) : 0;
                    mn.SetIntValue(next);
                }
                if (!WriteCurrentSaveImmediately(false)) return;
                AfterRelationWrite(string.Format("✅ 已和【{0}】解除结缘", name));
            }
        }

        private void SetMainCompanionAndWrite()
        {
            if (currentSlot == null) return;
            int nid = SelectedCompanionId(); if (nid < 0) return;
            string name = NpcName(nid);
            ReloadIfDiskChanged();
            var rel = GetRelationNode();
            if (rel == null) { MessageBox.Show(this, "存档里没找到关系数据。", "错误"); return; }
            if (!ReadIdList(rel.GetMapValue("dao_companion_npc_ids")).Contains(nid))
            {
                MessageBox.Show(this, string.Format("【{0}】还不是你的道侣，只能从已结缘的人里选主道侣。", name), "提示");
                return;
            }
            var mn = rel.GetMapValue("dao_companion_npc_id");
            if (mn != null && mn.AsInt64(0) == nid) { lblStatus.Text = name + " 已经是主道侣了。"; return; }
            if (mn != null) mn.SetIntValue(nid); else rel.SetMapValue("dao_companion_npc_id", MsgPackNode.CreateInt(nid));
            if (!WriteCurrentSaveImmediately(false)) return;
            AfterRelationWrite(string.Format("✅ 已把主道侣改为【{0}】", name));
        }

        private void SetHousingAndWrite(bool movein)
        {
            if (currentSlot == null) return;
            int nid = SelectedCompanionId(); if (nid < 0) return;
            string name = NpcName(nid);
            int room = cmbHouseRoom.SelectedIndex;
            ReloadIfDiskChanged();
            var res = GetHousingResidents(true);
            if (res == null) { MessageBox.Show(this, "存档里没找到洞府数据（可能还没开启小重天）。", "提示"); return; }
            if (movein)
            {
                if (room < 0) { MessageBox.Show(this, "请先选择房间。", "提示"); return; }
                if (!saveNpcMap.ContainsKey(nid)) { MessageBox.Show(this, "这个人不在当前存档里。", "提示"); return; }
                if (GetNpcSaveIntimacy(nid) < 100 && MessageBox.Show(this, string.Format("【{0}】好感不足 100（游戏里要 100 才能邀请；好感低于 0 会自己离开）。\n仍要让他/她入住吗？", name), "提醒", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                var occupant = res.GetMapValueByInt(room);
                if (occupant != null && occupant.AsInt64(0) > 0 && occupant.AsInt64(0) != nid &&
                    MessageBox.Show(this, string.Format("{0}现在住着【{1}】，要换成【{2}】吗？", HouseRoomNames[room], NpcName((int)occupant.AsInt64(0)), name), "确认", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                // 同一个人只能住一间：先从别的房间移出
                if (res.MapEntries.RemoveAll(kv => kv.Value.AsInt64(0) == nid && kv.Key.AsInt32(-1) != room) > 0) res.MarkModified();
                SetIntKeyValue(res, room, MsgPackNode.CreateInt(nid));
                if (!WriteCurrentSaveImmediately(false)) return;
                AfterRelationWrite(string.Format("✅ 【{0}】已入住洞府·{1}", name, HouseRoomNames[room]));
            }
            else
            {
                int n = res.MapEntries.RemoveAll(kv => kv.Value.AsInt64(0) == nid);
                if (n == 0) { lblStatus.Text = name + " 没有住在洞府里。"; return; }
                res.MarkModified();
                if (!WriteCurrentSaveImmediately(false)) return;
                AfterRelationWrite(string.Format("✅ 已请【{0}】离开洞府", name));
            }
        }

        private void BatchAndWrite(bool fullIntimacy, bool unlockSlots)
        {
            if (currentSlot == null) return;
            var ids = lvCompanions.Items.Cast<ListViewItem>().Select(x => (int)x.Tag).ToList();
            if (ids.Count == 0) { MessageBox.Show(this, "列表是空的。", "提示"); return; }
            if (MessageBox.Show(this, string.Format("确定对列表里的 {0} 个人{1}吗？", ids.Count, fullIntimacy ? "全部设为满好感(500)" : "解锁全部已有的天赋槽"), "批量操作", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
            ReloadIfDiskChanged();
            int changed = 0;
            foreach (var nid in ids)
            {
                MsgPackNode npc;
                if (!saveNpcMap.TryGetValue(nid, out npc)) continue;
                if (fullIntimacy)
                {
                    var node = npc.GetMapValue("intimacy");
                    if (node == null) { npc.SetMapValue("intimacy", MsgPackNode.CreateInt(MaxIntimacy)); changed++; }
                    else if (node.AsInt64(0) != MaxIntimacy) { node.SetIntValue(MaxIntimacy); changed++; }
                }
                if (unlockSlots)
                {
                    var t = npc.GetMapValue("talent");
                    var slots = t != null ? t.GetMapValue("slots") : null;
                    if (slots == null || slots.Kind != MsgPackKind.Array) continue;
                    bool any = false;
                    foreach (var s in slots.ArrayItems)
                    {
                        if (s.Kind != MsgPackKind.Map) continue;
                        var u = s.GetMapValue("unlocked");
                        if (u == null) { s.SetMapValue("unlocked", MsgPackNode.CreateBool(true)); any = true; }
                        else if (!u.AsBool(false)) { u.SetBoolValue(true); any = true; }
                    }
                    if (any) changed++;
                }
            }
            if (changed == 0) { lblStatus.Text = "列表里的人都已经是这个状态了，没有需要改的。"; return; }
            if (!WriteCurrentSaveImmediately(false)) return;
            AfterRelationWrite(string.Format("✅ 批量完成：{0} 个人{1}", changed, fullIntimacy ? "设为满好感" : "解锁了天赋槽"));
        }

        private void JumpToNpcEditor()
        {
            if (lvCompanions.SelectedItems.Count == 0) { MessageBox.Show(this, "请先在列表里选一个人。", "提示"); return; }
            int nid = (int)lvCompanions.SelectedItems[0].Tag;
            mainTabs.SelectedTab = npcTabPage;
            txtSearchNpc.Text = "";
            chkOnlyCompanion.Checked = false;
            chkOnlyInSave.Checked = true;
            RefreshNpcListView();
            foreach (ListViewItem it in lvNpcs.Items)
            {
                if ((int)it.Tag == nid) { it.Selected = true; it.Focused = true; it.EnsureVisible(); break; }
            }
            SelectNpc(nid);
        }

        // =========================================================================
        // 8.9 炼丹 / 炼器页
        //   丹方图鉴：pill_recipe_manual.alchemy_recipe_manual_entries {丹方ID: 记录}
        //     记录字段：recipe_id, craft_count, effect_ids(药效词条), best_grade, latest_condense_progress,
        //              toxin(丹毒), herb_stats(药材), first_recorded_at, last_crafted_at
        //     本工具只改 effect_ids / best_grade，以及补录没有的丹方；药材和丹毒不动
        //   炼丹天赋：refining_pills.rp_talent_ranks {天赋ID: 等级}
        //   丹药服用次数：refining_pills.rp_pill_use_count {丹药物品ID: 次数}
        // =========================================================================
        private ComboBox cmbRecipeFilter;
        private Label lblRecipeSummary;
        private ListView lvRecipes;
        private Label lblRecipeSel;
        private CheckedListBox clbPillEffects;
        private ComboBox cmbRecipeGrade;
        private Button btnRecipeWrite;
        private ListView lvPillTalents;
        private NumericUpDown numPillTalentRank;
        private ListView lvPillUse;
        private static readonly string[] GradeNames = { "", "凡品", "仙品", "神品" };

        private void BuildAlchemyTab(TabPage tab)
        {
            var sub = new TabControl { Dock = DockStyle.Fill };
            var tRecipe = new TabPage("📜 丹方图鉴（查漏补缺）");
            var tPill = new TabPage("⚗ 炼丹等级 / 丹炉 / 天赋 / 服用次数");
            var tForge = new TabPage("⚒ 炼器");
            sub.TabPages.AddRange(new[] { tRecipe, tPill, tForge });

            // ---------- 丹方图鉴 ----------
            var top = new Panel { Dock = DockStyle.Top, Height = 34 };
            var lf = new Label { Text = "显示：", Location = new Point(4, 9), AutoSize = true };
            cmbRecipeFilter = new ComboBox { Location = new Point(48, 5), Width = 200, DropDownStyle = ComboBoxStyle.DropDownList };
            cmbRecipeFilter.Items.AddRange(new object[] { "全部已开放丹方", "只看炼丹秘境的丹方", "未收录（全部）", "未收录 · 炼丹秘境能找到", "未收录 · 其他途径（奇遇等）", "已收录", "游戏未开放" });
            cmbRecipeFilter.SelectedIndex = 0;
            cmbRecipeFilter.SelectedIndexChanged += (s, e) => RefreshRecipeList();
            lblRecipeSummary = new Label { Location = new Point(262, 9), AutoSize = true, Font = new Font(Font, FontStyle.Bold), ForeColor = Color.FromArgb(45, 75, 110) };
            top.Controls.AddRange(new Control[] { lf, cmbRecipeFilter, lblRecipeSummary });

            lvRecipes = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = false };
            foreach (var c in new[] { new { t = "丹方", w = 100 }, new { t = "阶", w = 35 }, new { t = "五行", w = 45 }, new { t = "类别", w = 50 }, new { t = "来源", w = 90 }, new { t = "状态", w = 140 }, new { t = "最佳品级", w = 65 }, new { t = "药效词条", w = 160 }, new { t = "获取方向", w = 500 } })
                lvRecipes.Columns.Add(c.t, c.w);
            lvRecipes.SelectedIndexChanged += (s, e) => { if (lvRecipes.SelectedItems.Count > 0) SelectRecipe((int)lvRecipes.SelectedItems[0].Tag); };

            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 210 };
            lblRecipeSel = new Label { Location = new Point(4, 6), Size = new Size(1100, 22), Font = new Font(Font, FontStyle.Bold), ForeColor = Color.FromArgb(25, 65, 120), Text = "选一个丹方，可以修改它的药效词条和最佳品级；没收录的丹方可以补录进图鉴。" };
            var le = new Label { Text = "药效词条（打勾 = 有）：", Location = new Point(4, 32), AutoSize = true };
            clbPillEffects = new CheckedListBox { Location = new Point(4, 52), Size = new Size(620, 150), CheckOnClick = true, MultiColumn = false, HorizontalScrollbar = true };
            foreach (var ef in PillDatabase.Effects) clbPillEffects.Items.Add(ef);
            var lg = new Label { Text = "最佳品级：", Location = new Point(640, 56), AutoSize = true };
            cmbRecipeGrade = new ComboBox { Location = new Point(712, 52), Width = 90, DropDownStyle = ComboBoxStyle.DropDownList };
            cmbRecipeGrade.Items.AddRange(new object[] { "凡品", "仙品", "神品" });
            btnRecipeWrite = new Button { Text = "写入", Location = new Point(640, 90), Size = new Size(240, 34), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font(Font, FontStyle.Bold) };
            btnRecipeWrite.Click += (s, e) => WriteRecipeEntry();
            var lnote = new Label
            {
                Location = new Point(640, 132), Size = new Size(460, 70), ForeColor = Color.FromArgb(120, 90, 40),
                Text = "只改药效词条和最佳品级；药材记录、丹毒、炼制次数保持原样（要靠自己去炼）。\r\n补录的丹方：炼制次数记 1、丹毒 0、没有药材记录。"
            };
            bottom.Controls.AddRange(new Control[] { lblRecipeSel, le, clbPillEffects, lg, cmbRecipeGrade, btnRecipeWrite, lnote });

            tRecipe.Padding = new Padding(6);
            tRecipe.Controls.Add(lvRecipes);
            tRecipe.Controls.Add(bottom);
            tRecipe.Controls.Add(top);

            // ---------- 炼丹 ----------
            var pnlPill = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(8) };
            if (pillGroupForMove != null)
            {
                pillGroupForMove.Location = new Point(8, 8);
                pnlPill.Controls.Add(pillGroupForMove);
            }
            var grpT = new GroupBox { Text = "炼丹天赋", Location = new Point(460, 8), Size = new Size(700, 250) };
            lvPillTalents = new ListView { Location = new Point(10, 22), Size = new Size(680, 180), View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = false };
            foreach (var c in new[] { new { t = "天赋", w = 90 }, new { t = "阶段", w = 75 }, new { t = "效果", w = 250 }, new { t = "当前等级", w = 70 }, new { t = "最高", w = 45 }, new { t = "满级效果", w = 70 }, new { t = "满级需炼丹等级", w = 70 } })
                lvPillTalents.Columns.Add(c.t, c.w);
            lvPillTalents.SelectedIndexChanged += (s, e) =>
            {
                if (lvPillTalents.SelectedItems.Count == 0) return;
                var t = (PillTalentInfo)lvPillTalents.SelectedItems[0].Tag;
                numPillTalentRank.Maximum = t.Levels.Count;
                int cur; int.TryParse(lvPillTalents.SelectedItems[0].SubItems[3].Text, out cur);
                numPillTalentRank.Value = Math.Max(0, Math.Min(t.Levels.Count, cur));
            };
            var lr = new Label { Text = "选中天赋的等级：", Location = new Point(10, 214), AutoSize = true };
            numPillTalentRank = new NumericUpDown { Location = new Point(120, 210), Width = 60, Minimum = 0, Maximum = 5 };
            var btnRank = new Button { Text = "写入", Location = new Point(190, 207), Size = new Size(90, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnRank.Click += (s, e) => SetPillTalentAndWrite(false);
            var btnRankAll = new Button { Text = "全部天赋满级", Location = new Point(290, 207), Size = new Size(120, 30) };
            btnRankAll.Click += (s, e) => SetPillTalentAndWrite(true);
            grpT.Controls.AddRange(new Control[] { lvPillTalents, lr, numPillTalentRank, btnRank, btnRankAll });

            var grpU = new GroupBox { Text = "丹药服用次数（属性丹有服用上限，重置后可以继续吃）", Location = new Point(460, 268), Size = new Size(700, 250) };
            lvPillUse = new ListView { Location = new Point(10, 22), Size = new Size(680, 180), View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = true };
            foreach (var c in new[] { new { t = "丹药", w = 140 }, new { t = "已服用次数", w = 90 }, new { t = "丹方上限", w = 80 }, new { t = "物品ID", w = 80 } })
                lvPillUse.Columns.Add(c.t, c.w);
            var btnUse1 = new Button { Text = "重置选中的（可多选）", Location = new Point(10, 207), Size = new Size(190, 30), BackColor = Color.FromArgb(22, 120, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnUse1.Click += (s, e) => ResetPillUseAndWrite(false);
            var btnUseAll = new Button { Text = "全部重置", Location = new Point(210, 207), Size = new Size(100, 30) };
            btnUseAll.Click += (s, e) => ResetPillUseAndWrite(true);
            grpU.Controls.AddRange(new Control[] { lvPillUse, btnUse1, btnUseAll });
            pnlPill.Controls.AddRange(new Control[] { grpT, grpU });
            tPill.Controls.Add(pnlPill);

            // ---------- 炼器 ----------
            var pnlForge = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(8) };
            if (forgeGroupForMove != null)
            {
                forgeGroupForMove.Location = new Point(8, 8);
                pnlForge.Controls.Add(forgeGroupForMove);
            }
            tForge.Controls.Add(pnlForge);

            tab.Controls.Add(sub);
        }

        private MsgPackNode GetRecipeManualMap(bool create)
        {
            var pm = GetPlayerModelNode();
            if (pm == null) return null;
            var man = pm.GetMapValue("pill_recipe_manual");
            if (man == null || man.Kind != MsgPackKind.Map) return null;
            var ent = man.GetMapValue("alchemy_recipe_manual_entries");
            if ((ent == null || ent.Kind != MsgPackKind.Map) && create)
            {
                ent = MsgPackNode.CreateMap();
                man.SetMapValue("alchemy_recipe_manual_entries", ent);
            }
            return (ent != null && ent.Kind == MsgPackKind.Map) ? ent : null;
        }

        private MsgPackNode GetRefiningNode()
        {
            var pm = GetPlayerModelNode();
            var rp = pm != null ? pm.GetMapValue("refining_pills") : null;
            return (rp != null && rp.Kind == MsgPackKind.Map) ? rp : null;
        }

        private string EffectNames(MsgPackNode entry)
        {
            var ids = entry != null ? entry.GetMapValue("alchemy_recipe_manual_entry_effect_ids") : null;
            if (ids == null || ids.Kind != MsgPackKind.Array || ids.ArrayItems.Count == 0) return "";
            var names = new List<string>();
            foreach (var x in ids.ArrayItems)
            {
                var ef = PillDatabase.Effects.FirstOrDefault(e => e.Id == x.AsInt32(0));
                names.Add(ef != null ? ef.Name : x.AsString());
            }
            return string.Join("、", names);
        }

        private void RefreshAlchemyTab()
        {
            RefreshRecipeList();
            RefreshPillTalents();
            RefreshPillUse();
        }

        private void RefreshRecipeList()
        {
            if (lvRecipes == null) return;
            int keep = lvRecipes.SelectedItems.Count > 0 ? (int)lvRecipes.SelectedItems[0].Tag : -1;
            var ent = GetRecipeManualMap(false);
            string filter = cmbRecipeFilter.SelectedItem as string ?? "全部已开放丹方";
            bool mapOnly = filter == "只看炼丹秘境的丹方";
            int mapTotal = 0, mapHave = 0;
            int enabled = 0, recorded = 0;
            lvRecipes.BeginUpdate();
            lvRecipes.Items.Clear();
            foreach (var r in PillDatabase.Recipes.OrderBy(x => x.Enabled ? 0 : 1).ThenBy(x => x.Tier).ThenBy(x => x.Element).ThenBy(x => x.Id))
            {
                var e = ent != null ? ent.GetMapValueByInt(r.Id) : null;
                bool has = e != null;
                if (r.Enabled) { enabled++; if (has) recorded++; }
                bool onMap = r.Enabled && r.Source == "炼丹秘境";
                if (onMap) { mapTotal++; if (has) mapHave++; }
                if (filter == "全部已开放丹方" && !r.Enabled) continue;
                if (filter == "只看炼丹秘境的丹方" && !onMap) continue;
                if (filter == "未收录（全部）" && (!r.Enabled || has)) continue;
                if (filter == "未收录 · 炼丹秘境能找到" && (!onMap || has)) continue;
                if (filter == "未收录 · 其他途径（奇遇等）" && (!r.Enabled || has || onMap)) continue;
                if (filter == "已收录" && !has) continue;
                if (filter == "游戏未开放" && r.Enabled) continue;
                long cnt = has && e.GetMapValue("alchemy_recipe_manual_entry_craft_count") != null ? e.GetMapValue("alchemy_recipe_manual_entry_craft_count").AsInt64(0) : 0;
                int grade = has && e.GetMapValue("alchemy_recipe_manual_entry_best_grade") != null ? e.GetMapValue("alchemy_recipe_manual_entry_best_grade").AsInt32(0) : 0;
                var lvi = new ListViewItem(r.Name) { Tag = r.Id };
                lvi.SubItems.Add(r.Tier.ToString());
                lvi.SubItems.Add(PillDatabase.ElementName(r.Element));
                lvi.SubItems.Add(r.Category);
                lvi.SubItems.Add(r.Source);
                lvi.SubItems.Add(!r.Enabled ? "游戏未开放" : has ? string.Format("已收录（炼过 {0} 次）", cnt) : "❗ 未收录");
                lvi.SubItems.Add(has && grade > 0 && grade < GradeNames.Length ? GradeNames[grade] : "—");
                lvi.SubItems.Add(has ? EffectNames(e) : "");
                lvi.SubItems.Add(r.Hint);
                if (!r.Enabled) lvi.ForeColor = Color.Gray;
                else if (!has) lvi.ForeColor = Color.FromArgb(180, 70, 20);
                lvRecipes.Items.Add(lvi);
                if (r.Id == keep) lvi.Selected = true;
            }
            lvRecipes.EndUpdate();
            lblRecipeSummary.Text = mapOnly
                ? string.Format("炼丹秘境里的丹方 {0} 个，已收录 {1} 个，还差 {2} 个（橙色）", mapTotal, mapHave, mapTotal - mapHave)
                : string.Format("已开放丹方 {0} 个，已收录 {1} 个，还差 {2} 个（橙色）　|　其中炼丹秘境 {3} 个，已收录 {4} 个", enabled, recorded, enabled - recorded, mapTotal, mapHave);
        }

        private int selectedRecipeId = -1;

        private void SelectRecipe(int rid)
        {
            selectedRecipeId = rid;
            var r = PillDatabase.Recipes.FirstOrDefault(x => x.Id == rid);
            var ent = GetRecipeManualMap(false);
            var e = ent != null ? ent.GetMapValueByInt(rid) : null;
            var have = new HashSet<int>();
            var ids = e != null ? e.GetMapValue("alchemy_recipe_manual_entry_effect_ids") : null;
            if (ids != null && ids.Kind == MsgPackKind.Array) foreach (var x in ids.ArrayItems) have.Add(x.AsInt32(0));
            for (int i = 0; i < clbPillEffects.Items.Count; i++)
                clbPillEffects.SetItemChecked(i, have.Contains(((PillEffectInfo)clbPillEffects.Items[i]).Id));
            int grade = e != null && e.GetMapValue("alchemy_recipe_manual_entry_best_grade") != null ? e.GetMapValue("alchemy_recipe_manual_entry_best_grade").AsInt32(1) : 1;
            cmbRecipeGrade.SelectedIndex = Math.Max(0, Math.Min(2, grade - 1));
            btnRecipeWrite.Text = e != null ? "写入药效词条和品级" : "补录到丹方图鉴";
            btnRecipeWrite.Enabled = r != null && r.Enabled;
            lblRecipeSel.Text = r == null ? "" : string.Format("【{0}】{1}阶·{2}行·{3}　{4}　获取方向：{5}", r.Name, r.Tier, PillDatabase.ElementName(r.Element), r.Category,
                e != null ? "已收录" : (r.Enabled ? "未收录" : "游戏未开放"), r.Hint);
        }

        private void WriteRecipeEntry()
        {
            if (currentSlot == null || selectedRecipeId < 0) { MessageBox.Show(this, "请先在列表里选一个丹方。", "提示"); return; }
            int rid = selectedRecipeId;
            var r = PillDatabase.Recipes.FirstOrDefault(x => x.Id == rid);
            if (r == null || !r.Enabled) { MessageBox.Show(this, "这个丹方游戏还没开放。", "提示"); return; }
            var chosen = new List<int>();
            for (int i = 0; i < clbPillEffects.Items.Count; i++) if (clbPillEffects.GetItemChecked(i)) chosen.Add(((PillEffectInfo)clbPillEffects.Items[i]).Id);
            int grade = cmbRecipeGrade.SelectedIndex + 1;
            ReloadIfDiskChanged();
            var ent = GetRecipeManualMap(true);
            if (ent == null) { MessageBox.Show(this, "存档里没找到丹方图鉴数据。", "错误"); return; }
            var e = ent.GetMapValueByInt(rid);
            bool isNew = e == null;
            if (isNew)
            {
                long now = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
                e = MsgPackNode.CreateMap();
                e.SetMapValue("alchemy_recipe_manual_entry_recipe_id", MsgPackNode.CreateInt(rid));
                e.SetMapValue("alchemy_recipe_manual_entry_craft_count", MsgPackNode.CreateInt(1));
                e.SetMapValue("alchemy_recipe_manual_entry_effect_ids", MsgPackNode.CreateArray());
                e.SetMapValue("alchemy_recipe_manual_entry_best_grade", MsgPackNode.CreateInt(grade));
                e.SetMapValue("alchemy_recipe_manual_entry_latest_condense_progress", MsgPackNode.CreateInt(0));
                e.SetMapValue("alchemy_recipe_manual_entry_toxin", MsgPackNode.CreateInt(0));
                e.SetMapValue("alchemy_recipe_manual_entry_herb_stats", MsgPackNode.CreateMap());
                e.SetMapValue("alchemy_recipe_manual_entry_first_recorded_at", MsgPackNode.CreateInt(now));
                e.SetMapValue("alchemy_recipe_manual_entry_last_crafted_at", MsgPackNode.CreateInt(now));
                SetIntKeyValue(ent, rid, e);
            }
            // 药效：保留原来还勾着的（原顺序），新勾的加在后面
            var idsNode = e.GetMapValue("alchemy_recipe_manual_entry_effect_ids");
            var old = new List<int>();
            if (idsNode != null && idsNode.Kind == MsgPackKind.Array) foreach (var x in idsNode.ArrayItems) old.Add(x.AsInt32(0));
            var result = old.Where(chosen.Contains).ToList();
            foreach (var id in chosen) if (!result.Contains(id)) result.Add(id);
            if (!old.SequenceEqual(result))
                e.SetMapValue("alchemy_recipe_manual_entry_effect_ids", MsgPackNode.CreateArray(result.Select(x => MsgPackNode.CreateInt(x)).ToList()));
            var gNode = e.GetMapValue("alchemy_recipe_manual_entry_best_grade");
            if (gNode == null || gNode.AsInt32(0) != grade) e.SetMapValue("alchemy_recipe_manual_entry_best_grade", MsgPackNode.CreateInt(grade));

            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshRecipeList();
            SelectRecipe(rid);
            lblStatus.Text = string.Format("✅ {0}丹方【{1}】：药效 {2} 条、最佳品级 {3}，并写入 [{4}]。", isNew ? "已补录" : "已修改", r.Name, result.Count, GradeNames[grade], currentSlot.SlotName);
        }

        private void RefreshPillTalents()
        {
            if (lvPillTalents == null) return;
            int keep = lvPillTalents.SelectedIndices.Count > 0 ? lvPillTalents.SelectedIndices[0] : -1;
            var rp = GetRefiningNode();
            var ranks = rp != null ? rp.GetMapValue("rp_talent_ranks") : null;
            lvPillTalents.BeginUpdate();
            lvPillTalents.Items.Clear();
            foreach (var t in PillDatabase.Talents)
            {
                var v = ranks != null ? ranks.GetMapValueByInt(t.Id) : null;
                int cur = v != null ? v.AsInt32(0) : 0;
                var last = t.Levels.LastOrDefault();
                var lvi = new ListViewItem(t.Name) { Tag = t };
                lvi.SubItems.Add(t.Phase); lvi.SubItems.Add(t.Desc); lvi.SubItems.Add(cur.ToString()); lvi.SubItems.Add(t.Levels.Count.ToString());
                lvi.SubItems.Add(last != null ? last.Value : ""); lvi.SubItems.Add(last != null ? last.ReqLevel.ToString() : "");
                if (cur >= t.Levels.Count) lvi.ForeColor = Color.Gray;
                lvPillTalents.Items.Add(lvi);
            }
            lvPillTalents.EndUpdate();
            if (keep >= 0 && keep < lvPillTalents.Items.Count) lvPillTalents.Items[keep].Selected = true;
        }

        private void SetPillTalentAndWrite(bool all)
        {
            if (currentSlot == null) return;
            if (!all && lvPillTalents.SelectedItems.Count == 0) { MessageBox.Show(this, "请先选一个炼丹天赋。", "提示"); return; }
            var target = all ? null : (PillTalentInfo)lvPillTalents.SelectedItems[0].Tag;
            int rank = (int)numPillTalentRank.Value;
            ReloadIfDiskChanged();
            var rp = GetRefiningNode();
            if (rp == null) { MessageBox.Show(this, "存档里没找到炼丹数据。", "错误"); return; }
            var ranks = rp.GetMapValue("rp_talent_ranks");
            if (ranks == null || ranks.Kind != MsgPackKind.Map) { ranks = MsgPackNode.CreateMap(); rp.SetMapValue("rp_talent_ranks", ranks); }
            foreach (var t in PillDatabase.Talents)
            {
                if (!all && t != target) continue;
                int v = all ? t.Levels.Count : rank;
                var n = ranks.GetMapValueByInt(t.Id);
                if (n != null) { if (n.AsInt32(-1) != v) n.SetIntValue(v); }
                else if (v > 0) SetIntKeyValue(ranks, t.Id, MsgPackNode.CreateInt(v));
            }
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshPillTalents();
            lblStatus.Text = all ? string.Format("✅ 已把 {0} 个炼丹天赋全部升到满级，并写入 [{1}]。", PillDatabase.Talents.Count, currentSlot.SlotName)
                                 : string.Format("✅ 已把炼丹天赋【{0}】改为 {1} 级，并写入 [{2}]。", target.Name, rank, currentSlot.SlotName);
        }

        private void RefreshPillUse()
        {
            if (lvPillUse == null) return;
            var rp = GetRefiningNode();
            var use = rp != null ? rp.GetMapValue("rp_pill_use_count") : null;
            lvPillUse.BeginUpdate();
            lvPillUse.Items.Clear();
            if (use != null && use.Kind == MsgPackKind.Map)
            {
                foreach (var kv in use.MapEntries)
                {
                    int iid = kv.Key.AsInt32(0);
                    ItemInfo info; GameDatabase.Items.TryGetValue(iid, out info);
                    var r = PillDatabase.Recipes.FirstOrDefault(x => x.ItemId == iid);
                    var lvi = new ListViewItem(info != null ? info.Name : iid.ToString()) { Tag = iid };
                    lvi.SubItems.Add(kv.Value.AsInt64(0).ToString());
                    lvi.SubItems.Add(r != null && r.MaxUse > 0 ? r.MaxUse.ToString() : "—");
                    lvi.SubItems.Add(iid.ToString());
                    lvPillUse.Items.Add(lvi);
                }
            }
            lvPillUse.EndUpdate();
        }

        private void ResetPillUseAndWrite(bool all)
        {
            if (currentSlot == null) return;
            var ids = new HashSet<int>();
            foreach (ListViewItem it in (all ? lvPillUse.Items.Cast<ListViewItem>() : lvPillUse.SelectedItems.Cast<ListViewItem>())) ids.Add((int)it.Tag);
            if (ids.Count == 0) { MessageBox.Show(this, all ? "没有服用记录。" : "请先选中要重置的丹药（可按住 Ctrl 多选）。", "提示"); return; }
            ReloadIfDiskChanged();
            var rp = GetRefiningNode();
            var use = rp != null ? rp.GetMapValue("rp_pill_use_count") : null;
            if (use == null || use.Kind != MsgPackKind.Map) return;
            int n = use.MapEntries.RemoveAll(kv => ids.Contains(kv.Key.AsInt32(0)));
            if (n == 0) { lblStatus.Text = "没有需要重置的服用记录。"; return; }
            use.MarkModified();
            if (!WriteCurrentSaveImmediately(false)) return;
            RefreshPillUse();
            lblStatus.Text = string.Format("✅ 已重置 {0} 种丹药的服用次数，并写入 [{1}]。", n, currentSlot.SlotName);
        }

        // =========================================================================
        // 8.10 游戏难度
        //   gameworld：playerModel.game_difficulty_state.selected_difficulty_id
        //   meta.msgpack：gameDifficultyId（读档列表里显示的难度）
        //   各难度的隐藏增益不存进存档，游戏按难度 ID 实时计算
        // =========================================================================
        private static readonly string[] DifficultyNames = { "", "简单", "困难", "极难", "地狱", "灭世" };
        private static readonly string[] DifficultyDescs =
        {
            "",
            "造成所有伤害 +40%，受到所有伤害 -40%。适合体验剧情。",
            "标准档位，没有任何属性改动（游戏推荐首次游玩）。",
            "受到所有伤害 +20%，造成所有伤害 -20%。",
            "受到所有伤害 +35%，造成所有伤害 -35%；寿元不足时无法突破。",
            "受到所有伤害 +50%，造成所有伤害 -50%；寿元不足时无法突破；⚠ 死亡后角色存档会被永久删除！"
        };
        private ComboBox cmbDifficulty;
        private Label lblDifficultyInfo;

        private GroupBox BuildDifficultyGroup()
        {
            var grp = new GroupBox { Text = "游戏难度", Location = new Point(8, 186), Size = new Size(440, 170) };
            var l = new Label { Text = "难度：", Location = new Point(14, 30), AutoSize = true };
            cmbDifficulty = new ComboBox { Location = new Point(60, 26), Width = 160, DropDownStyle = ComboBoxStyle.DropDownList };
            for (int i = 1; i <= 5; i++) cmbDifficulty.Items.Add(i + " · " + DifficultyNames[i]);
            cmbDifficulty.SelectedIndexChanged += (s, e) =>
            {
                int id = cmbDifficulty.SelectedIndex + 1;
                if (id >= 1 && id <= 5) lblDifficultyInfo.Text = DifficultyDescs[id];
                lblDifficultyInfo.ForeColor = id == 5 ? Color.FromArgb(190, 40, 40) : Color.FromArgb(45, 75, 110);
            };
            var btn = new Button { Text = "写入难度", Location = new Point(230, 24), Size = new Size(110, 30), BackColor = ThemeGreen, ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btn.Click += (s, e) => SetDifficultyAndWrite();
            lblDifficultyInfo = new Label { Location = new Point(14, 64), Size = new Size(412, 50) };
            var note = new Label { Location = new Point(14, 118), Size = new Size(412, 44), ForeColor = Color.FromArgb(120, 90, 40), Text = "游戏说明：五个难度内容与奖励一致，只是挑战强度与失败条件不同。改难度会同时改存档本身和读档列表里显示的难度。" };
            grp.Controls.AddRange(new Control[] { l, cmbDifficulty, btn, lblDifficultyInfo, note });
            return grp;
        }

        private void RefreshDifficultyUI()
        {
            if (cmbDifficulty == null) return;
            var pm = GetPlayerModelNode();
            var st = pm != null ? pm.GetMapValue("game_difficulty_state") : null;
            var idn = st != null ? st.GetMapValue("selected_difficulty_id") : null;
            int id = idn != null ? idn.AsInt32(2) : 2;
            cmbDifficulty.SelectedIndex = Math.Max(0, Math.Min(4, id - 1));
        }

        // 修改 meta.msgpack 里的一个整数字段（原子写入）
        private static bool UpdateMetaIntField(string metaPath, string key, long value)
        {
            if (!File.Exists(metaPath)) return false;
            try
            {
                bool enc;
                byte[] plainMeta = SimpleSaveCrypto.DecryptOrPassThrough(File.ReadAllBytes(metaPath), out enc);
                var metaNode = MsgPackNode.Parse(plainMeta);
                if (metaNode.Kind != MsgPackKind.Map) return false;
                var n = metaNode.GetMapValue(key);
                if (n != null) n.SetIntValue(value); else metaNode.SetMapValue(key, MsgPackNode.CreateInt(value));
                byte[] newPlain = metaNode.ToBytes();
                WriteFileAtomic(metaPath, enc ? SimpleSaveCrypto.Encrypt(newPlain) : newPlain);
                return true;
            }
            catch { return false; }
        }

        private void SetDifficultyAndWrite()
        {
            if (currentSlot == null) return;
            int id = cmbDifficulty.SelectedIndex + 1;
            if (id < 1 || id > 5) return;
            if (id == 5 && MessageBox.Show(this,
                    "【灭世】难度：死亡后角色存档会被永久删除！\n（这是游戏本身的规则，编辑器的备份在【文档\\WorldApartSaveEditor_Backups】里，但游戏删档时不会通知编辑器）\n\n确定要把这个存档改成灭世难度吗？",
                    "危险操作", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;
            ReloadIfDiskChanged();
            var pm = GetPlayerModelNode();
            if (pm == null) return;
            var st = pm.GetMapValue("game_difficulty_state");
            if (st == null || st.Kind != MsgPackKind.Map)
            {
                st = MsgPackNode.CreateMap();
                st.SetMapValue("selected_difficulty_id", MsgPackNode.CreateInt(id));
                st.SetMapValue("state_version", MsgPackNode.CreateInt(1));
                pm.SetMapValue("game_difficulty_state", st);
            }
            else
            {
                var idn = st.GetMapValue("selected_difficulty_id");
                if (idn != null) idn.SetIntValue(id); else st.SetMapValue("selected_difficulty_id", MsgPackNode.CreateInt(id));
            }
            if (!WriteCurrentSaveImmediately(false)) return;
            bool metaOk = UpdateMetaIntField(currentSlot.MetaPath, "gameDifficultyId", id);
            RefreshDifficultyUI();
            lblStatus.Text = string.Format("✅ 已把难度改为【{0}】，并写入 [{1}]{2}。", DifficultyNames[id], currentSlot.SlotName, metaOk ? "（含读档列表显示）" : "（读档列表信息没能更新）");
        }

        // =========================================================================
        // 8.11 一键撤销 / 存档对比 / 支持作者
        // =========================================================================
        // ---------- 一键撤销：记住本次运行里每次写入前的备份，按顺序退回 ----------
        private readonly List<KeyValuePair<string, string>> undoStack = new List<KeyValuePair<string, string>>();  // (存档 gameworld 路径, 写入前备份目录)
        private Button btnUndo;

        private void PushUndo(string gameworldPath, string backupDir)
        {
            undoStack.Add(new KeyValuePair<string, string>(gameworldPath, backupDir));
            UpdateUndoButton();
        }

        private void UpdateUndoButton()
        {
            if (btnUndo == null) return;
            int n = currentSlot == null ? 0 : undoStack.Count(x => string.Equals(x.Key, currentSlot.GameWorldPath, StringComparison.OrdinalIgnoreCase));
            btnUndo.Text = n > 0 ? string.Format("撤销上一次修改（{0}）", n) : "撤销上一次修改";
            btnUndo.Enabled = n > 0;
        }

        private void UndoLastChange()
        {
            if (currentSlot == null) return;
            int idx = undoStack.FindLastIndex(x => string.Equals(x.Key, currentSlot.GameWorldPath, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) { MessageBox.Show(this, "这次打开编辑器后，还没有对这个存档做过修改。", "没有可撤销的"); return; }
            var item = undoStack[idx];
            string bgw = Path.Combine(item.Value, "gameworld.msgpack");
            string bmeta = Path.Combine(item.Value, "meta.msgpack");
            if (!File.Exists(bgw)) { MessageBox.Show(this, "找不到那次修改前的备份文件，没法撤销：\n" + item.Value, "错误"); undoStack.RemoveAt(idx); UpdateUndoButton(); return; }
            if (MessageBox.Show(this, string.Format("把存档 [{0}] 退回到上一次修改之前的状态吗？\n（现在的状态会先另存一份备份，不会丢）", currentSlot.SlotName), "撤销", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            isWritingDisk = true;
            try
            {
                CreateAutoBackup(currentSlot);   // 撤销前的状态也留一份
                WriteFileAtomic(currentSlot.GameWorldPath, File.ReadAllBytes(bgw));
                if (File.Exists(bmeta)) WriteFileAtomic(currentSlot.MetaPath, File.ReadAllBytes(bmeta));
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "撤销失败（存档没有被改动）：\n" + ex.Message, "错误");
                return;
            }
            finally { isWritingDisk = false; }
            undoStack.RemoveAt(idx);
            LoadSelectedSlot(false);
            UpdateUndoButton();
            lblStatus.Text = string.Format("↶ 已撤销上一次修改，存档 [{0}] 回到了修改前的状态。", currentSlot.SlotName);
        }

        // ---------- 存档对比 ----------
        private ComboBox cmbCmpA, cmbCmpB;
        private TextBox txtCmpFilter;
        private CheckBox chkCmpIgnoreNoise;
        private ListView lvCmp;
        private Label lblCmpSummary;
        private const int CmpMaxRows = 5000;
        private static readonly string[] CmpNoiseKeys = { "chat", "Chat", "timestamp", "Summary", "summary", "_at", "online_seconds", "cursor", "history", "History", "episode", "Episode", "memoria", "Messages", "seen", "visited", "cooldown", "_time", "Time", "_day", "_month", "fog", "strokes", "seed" };

        private void BuildCompareTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10) };
            var top = new Panel { Dock = DockStyle.Top, Height = 112 };
            var intro = new Label
            {
                Location = new Point(2, 4), Size = new Size(1100, 20), ForeColor = Color.FromArgb(45, 75, 110),
                Text = "选两个存档，列出它们之间哪些数值不一样。用法：在游戏里做一件事前后各存一次档，再拿来对比，就能找到这件事改了存档的哪里。"
            };
            var la = new Label { Text = "存档 A（之前）：", Location = new Point(2, 36), AutoSize = true };
            cmbCmpA = new ComboBox { Location = new Point(110, 32), Width = 470, DropDownStyle = ComboBoxStyle.DropDownList };
            var ba = MkBtn("浏览…", 588, 30, 70); ba.Click += (s, e) => BrowseCompareFile(cmbCmpA);
            var lb = new Label { Text = "存档 B（之后）：", Location = new Point(2, 70), AutoSize = true };
            cmbCmpB = new ComboBox { Location = new Point(110, 66), Width = 470, DropDownStyle = ComboBoxStyle.DropDownList };
            var bb = MkBtn("浏览…", 588, 64, 70); bb.Click += (s, e) => BrowseCompareFile(cmbCmpB);
            var bgo = MkBtn("开始对比", 672, 30, 120, true); bgo.Height = 64; bgo.Click += (s, e) => RunCompare();
            chkCmpIgnoreNoise = new CheckBox { Text = "忽略杂项（聊天记录、时间、冷却、迷雾、浏览记录等）", Location = new Point(806, 36), AutoSize = true, Checked = true };
            var lf = new Label { Text = "筛选：", Location = new Point(806, 70), AutoSize = true };
            txtCmpFilter = new TextBox { Location = new Point(850, 66), Width = 200 };
            txtCmpFilter.TextChanged += (s, e) => ApplyCompareFilter();
            top.Controls.AddRange(new Control[] { intro, la, cmbCmpA, ba, lb, cmbCmpB, bb, bgo, chkCmpIgnoreNoise, lf, txtCmpFilter });

            lvCmp = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false };
            lvCmp.Columns.Add("变化", 60); lvCmp.Columns.Add("位置", 560); lvCmp.Columns.Add("A（之前）", 240); lvCmp.Columns.Add("B（之后）", 240);
            lblCmpSummary = new Label { Dock = DockStyle.Bottom, Height = 26, TextAlign = ContentAlignment.MiddleLeft, Font = new Font(Font, FontStyle.Bold), ForeColor = Color.FromArgb(45, 75, 110) };
            pnl.Controls.Add(lvCmp); pnl.Controls.Add(lblCmpSummary); pnl.Controls.Add(top);
            tab.Controls.Add(pnl);
            tab.Enter += (s, e) => FillCompareCombos();
        }

        private void FillCompareCombos()
        {
            foreach (var cb in new[] { cmbCmpA, cmbCmpB })
            {
                var keep = cb.SelectedItem;
                var extra = cb.Items.Cast<object>().Where(x => !(x is SaveSlotEntry) || !cmbSlots.Items.Contains(x)).ToList();
                cb.Items.Clear();
                foreach (var x in cmbSlots.Items) cb.Items.Add(x);
                foreach (var x in extra) if (!cb.Items.Contains(x)) cb.Items.Add(x);
                if (keep != null && cb.Items.Contains(keep)) cb.SelectedItem = keep;
            }
            if (cmbCmpB.SelectedIndex < 0 && currentSlot != null && cmbCmpB.Items.Contains(currentSlot)) cmbCmpB.SelectedItem = currentSlot;
            if (cmbCmpA.SelectedIndex < 0 && cmbCmpA.Items.Count > 1) cmbCmpA.SelectedIndex = cmbCmpB.SelectedIndex == 0 ? 1 : 0;
        }

        private void BrowseCompareFile(ComboBox target)
        {
            using (var ofd = new OpenFileDialog { Title = "选择存档文件 gameworld.msgpack（也可以选备份里的）", Filter = "存档 (gameworld.msgpack)|gameworld.msgpack|所有文件 (*.*)|*.*" })
            {
                string docs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WorldApartSaveEditor_Backups");
                if (Directory.Exists(docs)) ofd.InitialDirectory = docs;
                if (ofd.ShowDialog(this) != DialogResult.OK) return;
                var entry = ReadSlotEntry(Path.GetDirectoryName(ofd.FileName), ofd.FileName);
                entry.SlotName = Path.GetFileName(Path.GetDirectoryName(ofd.FileName));
                target.Items.Add(entry);
                target.SelectedItem = entry;
            }
        }

        private class CmpRow { public string Kind; public string Path; public string A; public string B; }
        private List<CmpRow> cmpRows = new List<CmpRow>();

        private static MsgPackNode LoadSaveTree(string path)
        {
            bool enc;
            return MsgPackNode.Parse(SimpleSaveCrypto.DecryptOrPassThrough(File.ReadAllBytes(path), out enc));
        }

        private void RunCompare()
        {
            var a = cmbCmpA.SelectedItem as SaveSlotEntry;
            var b = cmbCmpB.SelectedItem as SaveSlotEntry;
            if (a == null || b == null) { MessageBox.Show(this, "请选好两个存档。", "提示"); return; }
            if (a.GameWorldPath == b.GameWorldPath) { MessageBox.Show(this, "两个选的是同一个存档。", "提示"); return; }
            Cursor = Cursors.WaitCursor;
            try
            {
                var ta = LoadSaveTree(a.GameWorldPath);
                var tb = LoadSaveTree(b.GameWorldPath);
                cmpRows = new List<CmpRow>();
                DiffNodes(ta, tb, "", chkCmpIgnoreNoise.Checked);
                ApplyCompareFilter();
            }
            catch (Exception ex) { MessageBox.Show(this, "对比失败：\n" + ex.Message, "错误"); }
            finally { Cursor = Cursors.Default; }
        }

        private static bool SameRaw(MsgPackNode a, MsgPackNode b)
        {
            if (a.SourceBuffer == null || b.SourceBuffer == null || a.IsModified || b.IsModified) return false;
            if (a.RawLength != b.RawLength) return false;
            for (int i = 0; i < a.RawLength; i++)
                if (a.SourceBuffer[a.RawOffset + i] != b.SourceBuffer[b.RawOffset + i]) return false;
            return true;
        }

        private static string KeyText(MsgPackNode k)
        {
            if (k.Kind == MsgPackKind.String) return k.StrVal;
            return k.AsString() ?? k.Kind.ToString();
        }

        private string ShortValue(MsgPackNode n)
        {
            if (n == null) return "（无）";
            switch (n.Kind)
            {
                case MsgPackKind.Nil: return "nil";
                case MsgPackKind.Bool: return n.BoolVal ? "是" : "否";
                case MsgPackKind.Int: return n.IntVal.ToString();
                case MsgPackKind.UInt: return n.UIntVal.ToString();
                case MsgPackKind.Float:
                case MsgPackKind.Double: return n.FloatVal.ToString("0.####");
                case MsgPackKind.String: return n.StrVal.Length > 60 ? n.StrVal.Substring(0, 60) + "…" : n.StrVal;
                case MsgPackKind.Map:
                    {
                        // 小的 Map 直接展开，方便看；带名字的东西给出名字
                        var id = n.GetMapValue("npcCfgId") ?? n.GetMapValue("item_id");
                        if (id != null)
                        {
                            NpcConfigInfo c; ItemInfo it;
                            if (n.GetMapValue("npcCfgId") != null && GameDatabase.Npcs.TryGetValue(id.AsInt32(0), out c)) return "{NPC " + c.Name + "}";
                            if (GameDatabase.Items.TryGetValue(id.AsInt32(0), out it)) return "{" + it.Name + " ×" + (n.GetMapValue("count") != null ? n.GetMapValue("count").AsString() : "?") + "}";
                        }
                        return "{" + n.MapEntries.Count + " 项}";
                    }
                case MsgPackKind.Array:
                    {
                        if (n.ArrayItems.Count <= 8 && n.ArrayItems.All(x => x.Kind == MsgPackKind.Int || x.Kind == MsgPackKind.UInt || x.Kind == MsgPackKind.String))
                            return "[" + string.Join(",", n.ArrayItems.Select(x => x.AsString())) + "]";
                        if (n.ArrayItems.Count == 2 && n.ArrayItems[1].Kind == MsgPackKind.Map) return ShortValue(n.ArrayItems[1]);
                        return "[" + n.ArrayItems.Count + " 项]";
                    }
                default: return n.Kind.ToString();
            }
        }

        // 给路径加上人能看懂的名字：npcs 下的 UUID 换成 NPC 名字，背包格子带上物品名
        private string LabelForChild(MsgPackNode parentPathNode, string key, MsgPackNode a, MsgPackNode b, string parentPath)
        {
            var probe = a ?? b;
            if (probe != null && probe.Kind == MsgPackKind.Map)
            {
                var id = probe.GetMapValue("npcCfgId");
                NpcConfigInfo c;
                if (id != null && GameDatabase.Npcs.TryGetValue(id.AsInt32(0), out c)) return "[" + c.Name + "]";
            }
            if (probe != null && probe.Kind == MsgPackKind.Array && probe.ArrayItems.Count == 2 && probe.ArrayItems[1].Kind == MsgPackKind.Map)
            {
                var iid = probe.ArrayItems[1].GetMapValue("item_id");
                ItemInfo it;
                if (iid != null && GameDatabase.Items.TryGetValue(iid.AsInt32(0), out it)) return "[" + key + "·" + it.Name + "]";
            }
            return null;
        }

        // 路径跟 NPC 有关时，把数字 ID 换成 "ID(名字)"
        private static string WithNpcName(string path, string v)
        {
            if (path.IndexOf("npc", StringComparison.OrdinalIgnoreCase) < 0 && path.IndexOf("resident", StringComparison.OrdinalIgnoreCase) < 0 && path.IndexOf("master", StringComparison.OrdinalIgnoreCase) < 0 && path.IndexOf("disciple", StringComparison.OrdinalIgnoreCase) < 0) return v;
            int id; NpcConfigInfo c;
            if (int.TryParse(v, out id) && GameDatabase.Npcs.TryGetValue(id, out c)) return v + "(" + c.Name + ")";
            return v;
        }

        private static string NpcIdsText(string path, IEnumerable<string> ids)
        {
            return string.Join(",", ids.Select(x => WithNpcName(path, x)));
        }

        private void AddCmp(string kind, string path, MsgPackNode a, MsgPackNode b)
        {
            if (cmpRows.Count >= CmpMaxRows) return;
            cmpRows.Add(new CmpRow { Kind = kind, Path = path.TrimStart('.'), A = a == null ? "（无）" : WithNpcName(path, ShortValue(a)), B = b == null ? "（无）" : WithNpcName(path, ShortValue(b)) });
        }

        private static bool IsNoiseKey(string key)
        {
            foreach (var n in CmpNoiseKeys) if (key.IndexOf(n, StringComparison.Ordinal) >= 0) return true;
            return false;
        }

        private void DiffNodes(MsgPackNode a, MsgPackNode b, string path, bool ignoreNoise)
        {
            if (cmpRows.Count >= CmpMaxRows) return;
            if (SameRaw(a, b)) return;
            if (a.Kind == MsgPackKind.Map && b.Kind == MsgPackKind.Map)
            {
                var bmap = new Dictionary<string, MsgPackNode>();
                foreach (var kv in b.MapEntries) bmap[KeyText(kv.Key)] = kv.Value;
                var seen = new HashSet<string>();
                foreach (var kv in a.MapEntries)
                {
                    string k = KeyText(kv.Key);
                    seen.Add(k);
                    if (ignoreNoise && IsNoiseKey(k)) continue;
                    MsgPackNode bv;
                    bmap.TryGetValue(k, out bv);
                    string label = LabelForChild(a, k, kv.Value, bv, path) ?? ((kv.Key.Kind == MsgPackKind.String) ? "." + k : "[" + k + "]");
                    if (label.StartsWith("[") && !label.StartsWith("[" + k)) label = "." + label;
                    string p = path + label;
                    if (bv == null) AddCmp("删除", p, kv.Value, null);
                    else DiffNodes(kv.Value, bv, p, ignoreNoise);
                }
                foreach (var kv in b.MapEntries)
                {
                    string k = KeyText(kv.Key);
                    if (seen.Contains(k) || (ignoreNoise && IsNoiseKey(k))) continue;
                    string label = LabelForChild(b, k, null, kv.Value, path) ?? ((kv.Key.Kind == MsgPackKind.String) ? "." + k : "[" + k + "]");
                    if (label.StartsWith("[") && !label.StartsWith("[" + k)) label = "." + label;
                    AddCmp("新增", path + label, null, kv.Value);
                }
                return;
            }
            if (a.Kind == MsgPackKind.Array && b.Kind == MsgPackKind.Array)
            {
                // 纯数字/文字的小数组：整体比较，显示成一行
                bool scalar = a.ArrayItems.Concat(b.ArrayItems).All(x => x.Kind == MsgPackKind.Int || x.Kind == MsgPackKind.UInt || x.Kind == MsgPackKind.String || x.Kind == MsgPackKind.Bool);
                if (scalar)
                {
                    var sa = a.ArrayItems.Select(x => x.AsString() ?? x.BoolVal.ToString()).ToList();
                    var sb = b.ArrayItems.Select(x => x.AsString() ?? x.BoolVal.ToString()).ToList();
                    var added = sb.Except(sa).ToList(); var removed = sa.Except(sb).ToList();
                    if (added.Count == 0 && removed.Count == 0 && sa.Count == sb.Count) { if (!sa.SequenceEqual(sb)) AddCmp("改变", path + "（顺序变化）", a, b); return; }
                    cmpRows.Add(new CmpRow { Kind = "改变", Path = path.TrimStart('.'), A = "共 " + sa.Count + " 项" + (removed.Count > 0 ? "，少了 " + NpcIdsText(path, removed.Take(20)) : ""), B = "共 " + sb.Count + " 项" + (added.Count > 0 ? "，多了 " + NpcIdsText(path, added.Take(20)) : "") });
                    return;
                }
                int n = Math.Max(a.ArrayItems.Count, b.ArrayItems.Count);
                for (int i = 0; i < n; i++)
                {
                    var av = i < a.ArrayItems.Count ? a.ArrayItems[i] : null;
                    var bv = i < b.ArrayItems.Count ? b.ArrayItems[i] : null;
                    string label = LabelForChild(a, i.ToString(), av, bv, path) ?? "[" + i + "]";
                    string p = path + label;
                    if (av == null) AddCmp("新增", p, null, bv);
                    else if (bv == null) AddCmp("删除", p, av, null);
                    else DiffNodes(av, bv, p, ignoreNoise);
                }
                return;
            }
            // 标量或类型不同
            string va = ShortValue(a), vb = ShortValue(b);
            if (va != vb || a.Kind != b.Kind) AddCmp("改变", path, a, b);
        }

        private void ApplyCompareFilter()
        {
            if (lvCmp == null) return;
            string kw = (txtCmpFilter.Text ?? "").Trim();
            lvCmp.BeginUpdate();
            lvCmp.Items.Clear();
            int shown = 0;
            foreach (var r in cmpRows)
            {
                if (kw.Length > 0 && r.Path.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0 && r.A.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0 && r.B.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0) continue;
                var lvi = new ListViewItem(r.Kind);
                lvi.SubItems.Add(r.Path); lvi.SubItems.Add(r.A); lvi.SubItems.Add(r.B);
                lvi.ForeColor = r.Kind == "新增" ? Color.FromArgb(30, 120, 60) : r.Kind == "删除" ? Color.FromArgb(180, 50, 40) : Color.FromArgb(40, 60, 90);
                lvCmp.Items.Add(lvi);
                shown++;
            }
            lvCmp.EndUpdate();
            lblCmpSummary.Text = cmpRows.Count == 0 ? "两个存档（在当前设置下）没有差异，或还没开始对比。"
                : string.Format("共 {0} 处不同{1}，当前显示 {2} 处。", cmpRows.Count, cmpRows.Count >= CmpMaxRows ? "（太多了，只列前 " + CmpMaxRows + " 处）" : "", shown);
        }

        // ---------- 支持作者 ----------
        private void BuildDonateTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Padding = new Padding(30) };
            var title = new Label { Text = "支持作者", Location = new Point(30, 24), AutoSize = true, Font = new Font("Microsoft YaHei UI", 16f, FontStyle.Bold), ForeColor = ThemeInk };
            var text = new Label
            {
                Location = new Point(30, 70), Size = new Size(760, 80), ForeColor = Color.FromArgb(50, 58, 70), Font = new Font("Microsoft YaHei UI", 10.5f),
                Text = "这个修改器免费使用。如果它帮到了你，可以扫下面的码请作者喝杯茶，完全自愿。\r\n修改器与《不问凡尘》官方无关，请支持正版游戏。"
            };
            var pic = new PictureBox { Location = new Point(30, 160), Size = new Size(320, 320), SizeMode = PictureBoxSizeMode.Zoom, BorderStyle = BorderStyle.FixedSingle, BackColor = Color.White };
            var hint = new Label { Location = new Point(370, 160), Size = new Size(420, 320), ForeColor = Color.FromArgb(120, 90, 40), Font = new Font("Microsoft YaHei UI", 10f) };
            // 收款码只认编译时打包进 exe 的 donate_qr.png，不读外部文件，防止被人换图
            Image img = null;
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("donate_qr.png"))
                    if (s != null) img = Image.FromStream(new MemoryStream(ReadAllStream(s)));
            }
            catch { img = null; }
            pic.Image = img;
            hint.Text = (img != null ? "这是马来西亚国家二维码（DuitNow），用 Touch 'n Go 或马来西亚任何银行 / 电子钱包 App 都能扫，谢谢支持！" : "（这个版本没有打包收款码）") +
                string.Format("\r\n\r\n作者：{0}\r\n官方发布地址：{1}\r\n\r\n只有从上面这个地址下载的才是原版。如果你是花钱买到的，或者这里的收款码、地址跟官方页面不一样，说明被人改过。", AuthorName, OfficialUrl);
            pnl.Controls.AddRange(new Control[] { title, text, pic, hint });
            tab.Controls.Add(pnl);
        }

        private static byte[] ReadAllStream(Stream s)
        {
            using (var ms = new MemoryStream()) { s.CopyTo(ms); return ms.ToArray(); }
        }

        // =========================================================================
        // 8.12 适配的游戏版本
        //   修改器的内置数据和存档格式是按下面这个游戏版本做的；游戏更新后可能需要更新修改器
        // =========================================================================
        public const string AuthorName = "Mastin-Ng";
        public const string OfficialUrl = "https://github.com/Mastin-Ng/WorldApartSaveEditor";
        public const string SteamAppId = "4209920";
        public const long TargetSteamBuild = 26646193;
        public const string TargetGameDate = "2026-11-14";
        public const string TargetSaveVersion = "2.0.0";
        public const long TargetContentVersion = 4;

        private long installedSteamBuild = -1;
        private string installedGameDate = "";

        // 在所有 Steam 库里找 appmanifest_4209920.acf，读出 buildid 和更新时间
        private void DetectInstalledGameVersion()
        {
            try
            {
                var libs = new List<string>();
                string steam = null;
                try
                {
                    using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam"))
                        if (k != null) steam = (k.GetValue("SteamPath") as string);
                }
                catch { }
                if (string.IsNullOrEmpty(steam)) steam = @"C:\Program Files (x86)\Steam";
                steam = steam.Replace('/', '\\');
                libs.Add(Path.Combine(steam, "steamapps"));
                string vdf = Path.Combine(steam, "steamapps", "libraryfolders.vdf");
                if (File.Exists(vdf))
                    foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(File.ReadAllText(vdf), "\"path\"\\s+\"([^\"]+)\""))
                        libs.Add(Path.Combine(m.Groups[1].Value.Replace("\\\\", "\\"), "steamapps"));
                foreach (var lib in libs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    string acf = Path.Combine(lib, "appmanifest_" + SteamAppId + ".acf");
                    if (!File.Exists(acf)) continue;
                    string txt = File.ReadAllText(acf);
                    var b = System.Text.RegularExpressions.Regex.Match(txt, "\"buildid\"\\s+\"(\\d+)\"");
                    var u = System.Text.RegularExpressions.Regex.Match(txt, "\"LastUpdated\"\\s+\"(\\d+)\"");
                    if (b.Success) installedSteamBuild = long.Parse(b.Groups[1].Value);
                    if (u.Success) installedGameDate = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(long.Parse(u.Groups[1].Value)).ToLocalTime().ToString("yyyy-MM-dd");
                    break;
                }
            }
            catch { }
        }

        private string VersionHeaderText()
        {
            string t = string.Format("适配游戏 Build {0}（{1}）", TargetSteamBuild, TargetGameDate);
            if (installedSteamBuild > 0 && installedSteamBuild != TargetSteamBuild)
                t += string.Format("　⚠ 你的游戏是 Build {0}（{1}），游戏已更新，部分功能可能不准", installedSteamBuild, installedGameDate);
            return t;
        }

        // 读档后检查存档格式
        private string CheckSaveVersion()
        {
            try
            {
                if (currentSlot == null || rootNode == null) return null;
                var cv = rootNode.GetMapValue("contentVersion");
                string metaVer = null;
                if (File.Exists(currentSlot.MetaPath))
                {
                    bool enc;
                    var meta = MsgPackNode.Parse(SimpleSaveCrypto.DecryptOrPassThrough(File.ReadAllBytes(currentSlot.MetaPath), out enc));
                    var v = meta.GetMapValue("version");
                    if (v != null) metaVer = v.AsString();
                }
                var problems = new List<string>();
                if (metaVer != null && metaVer != TargetSaveVersion) problems.Add("存档格式 " + metaVer + "（修改器按 " + TargetSaveVersion + " 做的）");
                if (cv != null && cv.AsInt64(-1) != TargetContentVersion) problems.Add("内容版本 " + cv.AsInt64(-1) + "（修改器按 " + TargetContentVersion + " 做的）");
                return problems.Count == 0 ? null : "⚠ 这个存档的" + string.Join("、", problems) + "，可能是新版游戏的存档，修改前请先备份。";
            }
            catch { return null; }
        }

        // =========================================================================
        // 9. 备份、还原与写入（只写选中的存档；原子写入；备份放在云同步目录之外）
        // =========================================================================
        private const int MaxTimedBackupsPerSlot = 20;

        // 备份目录：文档\WorldApartSaveEditor_Backups\<存档ID>\<槽位名>
        // 不能放在存档目录里：那里整个被 Steam 云同步，备份会占满云空间
        private static string GetBackupRoot(SaveSlotEntry slot)
        {
            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string storageName = "unknown";
            try
            {
                string slotsRoot = Path.GetDirectoryName(slot.SlotFolder);
                string storageRoot = Path.GetDirectoryName(slotsRoot);
                if (!string.IsNullOrEmpty(storageRoot)) storageName = Path.GetFileName(storageRoot);
            }
            catch { }
            return Path.Combine(docs, "WorldApartSaveEditor_Backups", storageName, slot.SlotName);
        }

        private static void CopySlotFilesTo(SaveSlotEntry slot, string dir)
        {
            Directory.CreateDirectory(dir);
            File.Copy(slot.GameWorldPath, Path.Combine(dir, "gameworld.msgpack"), true);
            if (File.Exists(slot.MetaPath))
                File.Copy(slot.MetaPath, Path.Combine(dir, "meta.msgpack"), true);
        }

        private string CreateAutoBackup(SaveSlotEntry slot)
        {
            string backupRoot = GetBackupRoot(slot);
            Directory.CreateDirectory(backupRoot);

            // 第一次修改这个槽位前的原始状态，永久保留
            string initBackupDir = Path.Combine(backupRoot, "backup_initial");
            if (!Directory.Exists(initBackupDir))
                CopySlotFilesTo(slot, initBackupDir);

            // 每次写入前的状态，按时间命名，只保留最近 MaxTimedBackupsPerSlot 份
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
            string timedDir = Path.Combine(backupRoot, "backup_" + stamp);
            CopySlotFilesTo(slot, timedDir);

            try
            {
                var timed = Directory.GetDirectories(backupRoot, "backup_2*")
                    .OrderByDescending(d => Path.GetFileName(d), StringComparer.Ordinal)
                    .Skip(MaxTimedBackupsPerSlot)
                    .ToList();
                foreach (var old in timed)
                    Directory.Delete(old, true);
            }
            catch { }

            return timedDir;
        }

        private void ManualBackupCurrentSlot()
        {
            if (currentSlot == null) return;
            try
            {
                string bdir = Path.Combine(GetBackupRoot(currentSlot), "manual_backup_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                CopySlotFilesTo(currentSlot, bdir);
                lblStatus.Text = "已手动备份当前存档至：" + bdir;
                MessageBox.Show(this, "存档已成功备份至：\n" + bdir, "备份成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "备份失败：\n" + ex.Message, "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RestoreFromBackup()
        {
            if (currentSlot == null) return;
            string backupRoot = GetBackupRoot(currentSlot);
            using (var ofd = new OpenFileDialog())
            {
                ofd.Title = "选择要还原的备份文件 gameworld.msgpack";
                ofd.Filter = "备份存档 (gameworld.msgpack)|gameworld.msgpack";
                ofd.InitialDirectory = Directory.Exists(backupRoot) ? backupRoot : currentSlot.SlotFolder;

                if (ofd.ShowDialog(this) != DialogResult.OK) return;
                if (MessageBox.Show(this, string.Format("确定要用选中的备份覆盖存档 [{0}] 吗？\n（覆盖前会先把现在的存档再备份一次）", currentSlot.SlotName),
                        "确认还原", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

                isWritingDisk = true;
                try
                {
                    CreateAutoBackup(currentSlot);
                    WriteFileAtomic(currentSlot.GameWorldPath, File.ReadAllBytes(ofd.FileName));
                    string bMeta = Path.Combine(Path.GetDirectoryName(ofd.FileName), "meta.msgpack");
                    if (File.Exists(bMeta))
                        WriteFileAtomic(currentSlot.MetaPath, File.ReadAllBytes(bMeta));
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "还原失败：\n" + ex.Message, "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                finally
                {
                    isWritingDisk = false;
                }

                LoadSelectedSlot(false);
                MessageBox.Show(this, "已成功从备份还原存档！", "还原成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        // 原子写入：先写临时文件，再整体替换。写到一半崩溃/断电也不会留下半个坏存档
        private static void WriteFileAtomic(string path, byte[] data)
        {
            string tmp = path + ".editor_tmp";
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(data, 0, data.Length);
                fs.Flush(true);
            }
            if (File.Exists(path))
                File.Replace(tmp, path, null);
            else
                File.Move(tmp, path);
        }

        // 游戏 meta 里的 saveTime / accessTime 单位是【毫秒】（13 位数）。写成秒会显示成 1970 年
        private static void UpdateMetaTimestamps(string metaPath, long nowUnixMs)
        {
            if (!File.Exists(metaPath)) return;
            try
            {
                bool enc;
                byte[] rawMeta = File.ReadAllBytes(metaPath);
                byte[] plainMeta = SimpleSaveCrypto.DecryptOrPassThrough(rawMeta, out enc);
                var metaNode = MsgPackNode.Parse(plainMeta);
                if (metaNode.Kind != MsgPackKind.Map) return;

                var st = metaNode.GetMapValue("saveTime");
                if (st != null) st.SetIntValue(nowUnixMs);
                var at = metaNode.GetMapValue("accessTime");
                if (at != null) at.SetIntValue(nowUnixMs);

                byte[] newPlain = metaNode.ToBytes();
                byte[] newOut = enc ? SimpleSaveCrypto.Encrypt(newPlain) : newPlain;
                WriteFileAtomic(metaPath, newOut);
            }
            catch { }
        }

        private static bool IsGameRunning()
        {
            try
            {
                return System.Diagnostics.Process.GetProcessesByName("WorldApart").Length > 0;
            }
            catch
            {
                return false;
            }
        }

        // 只写入当前选中的这一个存档。返回是否成功
        private bool WriteCurrentSaveImmediately(bool showPopup)
        {
            if (currentSlot == null || rootNode == null) return false;

            if (!warnedGameRunning && IsGameRunning())
            {
                warnedGameRunning = true;
                var r = MessageBox.Show(this,
                    "检测到游戏正在运行。\n\n" +
                    "游戏开着时改存档，游戏下次自动存档 / 手动存档可能会把你的修改覆盖掉。\n" +
                    "最稳妥的做法是先关掉游戏再改。\n\n" +
                    "如果继续：写入后请马上在游戏里【读取这个存档】(" + currentSlot.SlotName + ")。\n\n" +
                    "确定继续写入吗？（本次运行不再提醒）",
                    "游戏正在运行", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (r != DialogResult.Yes)
                {
                    lblStatus.Text = "已取消写入。修改还在内存里，关掉游戏后点【保存到选中存档】即可写入。";
                    return false;
                }
            }

            isWritingDisk = true;
            try
            {
                Cursor = Cursors.WaitCursor;
                string backupDir = CreateAutoBackup(currentSlot);

                byte[] newPlainBytes = rootNode.ToBytes();
                // 写回前自检：能重新解析，才写
                MsgPackNode.Parse(newPlainBytes);
                byte[] outBytes = currentWasEncrypted ? SimpleSaveCrypto.Encrypt(newPlainBytes) : newPlainBytes;

                WriteFileAtomic(currentSlot.GameWorldPath, outBytes);
                long nowUnixMs = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
                UpdateMetaTimestamps(currentSlot.MetaPath, nowUnixMs);

                lastKnownDiskWriteUtc = File.GetLastWriteTimeUtc(currentSlot.GameWorldPath);
                PushUndo(currentSlot.GameWorldPath, backupDir);

                lblStatus.Text = string.Format("{0} 已写入存档 [{1}]，原档已备份。",
                    DateTime.Now.ToString("HH:mm:ss"), currentSlot.SlotName);

                if (showPopup)
                {
                    MessageBox.Show(this,
                        string.Format("修改已写入！\n\n• 存档：{0} ({1})\n• 写入前的备份：\n  {2}\n\n打开游戏读取这个存档即可生效。",
                            currentSlot.SlotName, currentSlot.CharacterName, backupDir),
                        "保存成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "写入存档时发生错误（存档没有被改动）：\n" + ex.Message, "写入失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                try { ReloadCurrentSlotFromDisk(); RefreshDaoTabUI(); RefreshNpcListView(); } catch { }
                return false;
            }
            finally
            {
                isWritingDisk = false;
                Cursor = Cursors.Default;
            }
        }
    }

    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            GameDatabase.LoadEmbedded();

            if (args != null && args.Length > 0 && args[0] == "--selftest")
            {
                RunSelfTest();
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }

        private static void RunSelfTest()
        {
            Console.WriteLine("Loaded Talents: " + GameDatabase.Talents.Count);
            Console.WriteLine("Loaded NPCs: " + GameDatabase.Npcs.Count);
            Console.WriteLine("Loaded DaoPath Nodes: " + GameDatabase.DaoNodes.Count);
            Console.WriteLine("SELFTEST_V2.0_OK");
        }
    }
}
