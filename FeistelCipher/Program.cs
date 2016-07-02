using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FeistelCipher
{
    public class Program
    {
        static void Main(string[] args)
        {
            //10010110
            byte msg = 150;
            PrintOutByte("msg: ", msg);

            byte[] keys = { 15, 1, 19 , 3 , 9 , 17, 10 };

            var encrypted = Encrypt(msg, FunctionF, keys);
            PrintOutByte("enc: ", encrypted);

            var decrypted = Decrypt(encrypted, FunctionF, keys);
            PrintOutByte("dec: ", decrypted);

            if (msg == decrypted)
                Console.WriteLine("Success");
            else
                Console.WriteLine("Fail");

            Console.ReadLine();
        }

        #region Feistel

        private static byte Encrypt(byte msg, Func<byte, byte, byte> FunctionF, byte[] keys)
        {
            byte step = msg;
            for (int i = 0; i < keys.Length; i++)
            {
                step = FeistelStepEncrypt(step, keys[i], FunctionF);
            }

            return step;
        }

        private static byte Decrypt(byte msg, Func<byte, byte, byte> FunctionF, byte[] keys)
        {
            byte step = msg;
            for (int i = keys.Length - 1; i >= 0; i--)
            {
                step = FeistelStepDecrypt(step, keys[i], FunctionF);
                step = InversionLR(step);
            }

            return step;
        }

        private static byte FunctionF(byte x, byte key)
        {
            return Xor(x, key);
        }


        private static byte FeistelStepEncrypt(byte msg, byte key, Func<byte, byte, byte> FunctionF)
        {
            var R = GetR(msg);
            var L = GetL(msg);
            //PrintOutByte("R: ", R);
            //PrintOutByte("L: ", L);

            var oper = OperateR(R, key, FunctionF);
            //PrintOutByte("oper: ", oper);

            var oper2 = OperateL(L, oper, Xor);
            //PrintOutByte("R enc: ", oper2);

            var fresnelParc = InversionLR(oper2, R);
            //PrintOutByte("Parc: ", fresnelParc);

            return fresnelParc;
        }

        private static byte FeistelStepDecrypt(byte msg, byte key, Func<byte, byte, byte> FunctionF)
        {
            var inv = InversionLR(msg);

            var fresnelParc = FeistelStepEncrypt(inv, key, FunctionF);

            return fresnelParc;
        }

        #endregion

        #region Bit Manipulation

        private static byte Xor(byte x, byte y)
        {
            return (byte)((int)x ^ (int)y);
        }

        private static byte GetR(byte x)
        {
            var temp = (byte)(((int)x) << 4);
            return (byte)(((int)temp) >> 4);
        }

        private static byte GetL(byte x)
        {
            var temp = (byte)(((int)x) >> 4);
            return (byte)(((int)temp) << 4);
        }

        private static byte InversionLR(byte l, byte r)
        {
            l = (byte)(((int)l) >> 4);
            r = (byte)(((int)r) << 4);
            return Xor(r, l);
        }

        private static byte InversionLR(byte msg)
        {
            var R = GetR(msg);
            var L = GetL(msg);
            return InversionLR(L, R);
        }

        private static byte OperateL(byte l, byte key, Func<byte, byte, byte> function)
        {
            key = (byte)(((int)key) << 4);
            return function(l, key);
        }

        private static byte OperateR(byte r, byte key, Func<byte, byte, byte> function)
        {
            return function(r, key);
        }

        #endregion

        #region Util

        private static void PrintOutByte(string initialText, byte x)
        {
            var temp = (int)x;
            int bits = 0;
            int factor = 1;
            for (int i = 7; i >= 0; i--)
            {
                bits += (temp % 2) * factor;
                factor *= 10;
                temp /= 2;
            }
            Console.WriteLine(initialText + "\t" + bits.ToString("00000000") + "\n");
        }

        private static byte EnsureKeyHas4Bits(byte key)
        {
            return (byte)((int)key % 16);
        }

        #endregion

    }
}
