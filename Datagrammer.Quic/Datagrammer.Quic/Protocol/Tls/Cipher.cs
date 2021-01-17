using Datagrammer.Quic.Protocol.Error;
using Datagrammer.Quic.Protocol.Tls.Aeads;
using Datagrammer.Quic.Protocol.Tls.Ciphers;
using Datagrammer.Quic.Protocol.Tls.Hashes;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Datagrammer.Quic.Protocol.Tls
{
    //      | Algorithm          | Reference | Key Size | Nonce Size | Tag Size | Max. Plaintext Size |
    //      | ------------------ | --------- | -------- | ---------- | -------- | ------------------- |
    //      | ChaCha20-Poly1305  | RFC 8439  | 32       | 12         | 16       | 2^38-64             |
    //      | AES-128-CCM        | RFC 5116  | 16       | 12         | 16       | 2^24-1              |
    //      | AES-256-CCM        | RFC 5116  | 32       | 12         | 16       | 2^24-1              |
    //      | AES-128-GCM        | RFC 5116  | 16       | 12         | 16       | 2^36-31             |
    //      | AES-256-GCM        | RFC 5116  | 32       | 12         | 16       | 2^36-31             |
    //      | AES-128-OCB        | RFC 7253  | 16       | 1..15      | 8,12,16  | unbounded           |
    //      | AES-192-OCB        | RFC 7253  | 24       | 1..15      | 8,12,16  | unbounded           |
    //      | AES-256-OCB        | RFC 7253  | 32       | 1..15      | 8,12,16  | unbounded           |
    public readonly struct Cipher : IEquatable<Cipher>
    {
        private static Cipher[] supported = new Cipher[] { TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256 };

        private static Dictionary<ushort, ICipherHash> hashes = new Dictionary<ushort, ICipherHash>
        {
            [0x1301] = new Hash(HashAlgorithmName.SHA256, 16, 12),
            [0x1303] = new Hash(HashAlgorithmName.SHA256, 32, 12)
        };

        private static Dictionary<ushort, Func<ReadOnlyMemory<byte>, ICipher>> cipherFactories = new Dictionary<ushort, Func<ReadOnlyMemory<byte>, ICipher>>
        {
            [0x1301] = (key) => AesEcbIntrinsicsCipher.IsSupported ? new AesEcbIntrinsicsCipher(key) : new Aes128EcbCipher(key),
            [0x1303] = (key) => new ChaCha20Cipher(key)
        };

        private static Dictionary<ushort, Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, IAead>> aeadFactories = new Dictionary<ushort, Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, IAead>>
        {
            [0x1301] = (iv, key) => new AesGcmAead(iv, key),
            [0x1303] = (iv, key) => new ChaCha20Poly1305Aead(iv, key)
        };

        private readonly ushort code;

        private Cipher(ushort code)
        {
            this.code = code;
        }

        public static Cipher Parse(ref ReadOnlyMemory<byte> bytes)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            bytes = bytes.Slice(2);

            return new Cipher(code);
        }

        public static Cipher Parse(MemoryCursor cursor)
        {
            var codeBytes = cursor.Move(2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            return new Cipher(code);
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var bytes = cursor.Move(2);

            NetworkBitConverter.WriteUnaligned(bytes.Span, code, 2);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            var writtenLength = NetworkBitConverter.WriteUnaligned(bytes, code, 2);

            bytes = bytes.Slice(writtenLength);
        }

        public static Cipher TLS_AES_128_GCM_SHA256 { get; } = new Cipher(0x1301);

        public static Cipher TLS_AES_256_GCM_SHA384 { get; } = new Cipher(0x1302);

        public static Cipher TLS_CHACHA20_POLY1305_SHA256 { get; } = new Cipher(0x1303);

        public static ReadOnlyMemory<Cipher> Supported => supported;

        public ICipherHash GetHash()
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

        public ICipher CreateCipher(ReadOnlyMemory<byte> key)
        {
            if (cipherFactories.TryGetValue(code, out var factory))
            {
                return factory(key);
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
