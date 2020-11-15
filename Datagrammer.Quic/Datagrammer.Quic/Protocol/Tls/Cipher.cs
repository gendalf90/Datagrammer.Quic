using Datagrammer.Quic.Protocol.Error;
using Datagrammer.Quic.Protocol.Tls.Aeads;
using Datagrammer.Quic.Protocol.Tls.Hashes;
using System;
using System.Collections.Generic;
using System.IO;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct Cipher : IEquatable<Cipher>
    {
        private static Dictionary<ushort, IHash> hashes = new Dictionary<ushort, IHash>
        {
            [0x1301] = Hash.Sha256
        };

        private static Dictionary<ushort, Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, IAead>> aeadFactories = new Dictionary<ushort, Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, IAead>>
        {
            [0x1301] = (iv, key) => new AesGcmAead(iv, key)
        };

        private readonly ushort code;

        private Cipher(ushort code)
        {
            this.code = code;
        }

        public static Cipher Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            remainings = bytes.Slice(2);

            return new Cipher(code);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            var writtenLength = NetworkBitConverter.WriteUnaligned(bytes, code, 2);

            bytes = bytes.Slice(writtenLength);
        }

        public void WriteBytes(Stream stream)
        {
            NetworkBitConverter.WriteUnaligned(stream, code, 2);
        }

        public static Cipher TLS_AES_128_GCM_SHA256 { get; } = new Cipher(0x1301);

        public static Cipher TLS_AES_256_GCM_SHA384 { get; } = new Cipher(0x1302);

        public static Cipher TLS_CHACHA20_POLY1305_SHA256 { get; } = new Cipher(0x1303);

        public static IEnumerable<Cipher> Supported { get; } = new HashSet<Cipher> { TLS_AES_128_GCM_SHA256 };

        public IHash GetHash()
        {
            if(hashes.TryGetValue(code, out var hash))
            {
                return hash;
            }

            throw new NotSupportedException();
        }

        public IAead CreateAead(ReadOnlyMemory<byte> iv, ReadOnlyMemory<byte> key)
        {
            if(aeadFactories.TryGetValue(code, out var factory))
            {
                return factory(iv, key);
            }

            throw new NotSupportedException();
        }

        public bool Equals(Cipher other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is Cipher version && Equals(version);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(Cipher first, Cipher second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(Cipher first, Cipher second)
        {
            return !first.Equals(second);
        }
    }
}
