using System;

namespace Datagrammer.Quic.Protocol.Tls.Ciphers
{
    public class ChaCha20Cipher : ICipher
    {
        private const int MaskLength = 5;
        private const int CounterLength = 4;
        private const int SampleLength = 16;
        private const int StateLength = 16;
        private const int KeyLength = 32;
        private const int NonceLength = 12;
        private const int ProcessingBytesLength = 64;

        private readonly ReadOnlyMemory<byte> key;

		public ChaCha20Cipher(ReadOnlyMemory<byte> key)
        {
			if (key.Length != KeyLength)
			{
				throw new ArgumentOutOfRangeException(nameof(key));
			}

			this.key = key;
        }

		public int CreateMask(ReadOnlySpan<byte> sample, Span<byte> destination)
		{
			if (sample.Length != SampleLength)
            {
				throw new ArgumentOutOfRangeException(nameof(sample));
            }

			if (destination.Length < MaskLength)
            {
				throw new ArgumentOutOfRangeException(nameof(destination));
            }

			var counter = BitConverter.ToUInt32(sample.Slice(0, CounterLength));
			var nonce = sample.Slice(CounterLength, NonceLength);

			Span<uint> state = stackalloc uint[StateLength];

			KeySetup(key.Span, state);
			IvSetup(nonce, counter, state);

			var maskBytes = destination.Slice(0, MaskLength);

			maskBytes.Clear();

			ProcessBytes(state, maskBytes);

			return maskBytes.Length;
		}

        public void Dispose()
        {
        }

		private void IvSetup(ReadOnlySpan<byte> nonce, uint counter, Span<uint> state)
		{
			state[12] = counter;

			for (int i = 0, j = 13; i < 3; i++, j++)
			{
				state[j] = BitConverter.ToUInt32(nonce.Slice(i * 4, 4));
			}
		}

		private void KeySetup(ReadOnlySpan<byte> key, Span<uint> state)
		{
			state[0] = 0x61707865;
			state[1] = 0x3320646e;
			state[2] = 0x79622d32;
			state[3] = 0x6b206574;

			for (int i = 0, j = 4; i < 8; i++, j++)
            {
				state[j] = BitConverter.ToUInt32(key.Slice(i * 4, 4));
			}
		}

		private void ProcessBytes(Span<uint> state, Span<byte> bytes)
		{
			var processedBytesLength = bytes.Length;
			var processedBytesOffset = 0;

			ref uint stateCounter = ref state[12];
			ref uint nonceCounter = ref state[13];

			Span<uint> stateBuffer = stackalloc uint[StateLength];
			Span<byte> processingBuffer = stackalloc byte[ProcessingBytesLength];

			unchecked
            {
				while (processedBytesLength > 0)
				{
					state.CopyTo(stateBuffer);

					for (int i = 0; i < 10; i++)
					{
						QuarterRound(ref stateBuffer[0], ref stateBuffer[4], ref stateBuffer[8], ref stateBuffer[12]);
						QuarterRound(ref stateBuffer[1], ref stateBuffer[5], ref stateBuffer[9], ref stateBuffer[13]);
						QuarterRound(ref stateBuffer[2], ref stateBuffer[6], ref stateBuffer[10], ref stateBuffer[14]);
						QuarterRound(ref stateBuffer[3], ref stateBuffer[7], ref stateBuffer[11], ref stateBuffer[15]);
						QuarterRound(ref stateBuffer[0], ref stateBuffer[5], ref stateBuffer[10], ref stateBuffer[15]);
						QuarterRound(ref stateBuffer[1], ref stateBuffer[6], ref stateBuffer[11], ref stateBuffer[12]);
						QuarterRound(ref stateBuffer[2], ref stateBuffer[7], ref stateBuffer[8], ref stateBuffer[13]);
						QuarterRound(ref stateBuffer[3], ref stateBuffer[4], ref stateBuffer[9], ref stateBuffer[14]);
					}

					for (int i = 0; i < StateLength; i++)
					{
						BitConverter.TryWriteBytes(processingBuffer.Slice(i * 4, 4), stateBuffer[i] + state[i]);
					}

					if (++stateCounter <= 0)
					{
						nonceCounter++;
					}

					if (processedBytesLength <= ProcessingBytesLength)
					{
						for (int i = 0; i < processedBytesLength; i++)
						{
							bytes[i + processedBytesOffset] = (byte)(bytes[i + processedBytesOffset] ^ processingBuffer[i]);
						}

						return;
					}

					for (int i = 0; i < ProcessingBytesLength; i++)
					{
						bytes[i + processedBytesOffset] = (byte)(bytes[i + processedBytesOffset] ^ processingBuffer[i]);
					}

					processedBytesLength -= ProcessingBytesLength;
					processedBytesOffset += ProcessingBytesLength;
				}
			}
		}

		private void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
		{
			a += b;
			d = Rotate(d ^ a, 16);
			c += d;
			b = Rotate(b ^ c, 12);
			a += b;
			d = Rotate(d ^ a, 8);
			c += d;
			b = Rotate(b ^ c, 7);
		}

		private uint Rotate(uint v, int c)
		{
			return (v << c) | (v >> (32 - c));
		}
	}
}
