/*
    版权所有（c）2021 starry  此程序是为了扩展 c# 语言中确实的加密算法
    特此向任何获得副本的人免费授予许可
    本软件和相关文档文件（“软件”）的
    在软件中不受限制，包括但不限于权利
    使用、复制、修改、合并、发布、分发、再许可和/或销售
    软件的副本，并允许向其提供软件的人员
    按照以下条件提供：
    上述版权声明和本许可声明应包含在
    软件的所有副本或主要部分。
    本软件按“原样”提供，无任何形式的明示或明示担保
    默示，包括但不限于适销性保证，
    适用于特定目的和非侵权。
 */

using System;
using System.Security.Cryptography;

namespace PBKDF2.Key.Security
{
    /// <summary>
    /// 内部实用程序/助手类
    /// </summary>
    internal static class Utils
    {
        #region fields

        private static RNGCryptoServiceProvider _rng = null;

        #endregion

        #region properties

        /// <summary>
        /// 提供对静态RngCryptoServiceProvider的访问。 
        /// </summary>
        internal static RNGCryptoServiceProvider StaticRngCryptoService
        {
            get
            {
                if (_rng == null)
                    _rng = new RNGCryptoServiceProvider();
                return _rng;
            }
        }

        #endregion

        #region methods

        ///<summary>
        /// 将整数编码成4字节数组，在大字节中。
        ///</summary>
        ///<param name=“i”>要编码的整数。</param>
        ///<returns>字节数组，以大端为单位。</returns>
        internal static byte[] GetBigEndianBytes(uint i)
        {
            byte[] b = BitConverter.GetBytes(i);
            byte[] invertedBytes = { b[3], b[2], b[1], b[0] };
            return BitConverter.IsLittleEndian ? invertedBytes : b;
        }

        ///<summary>
        /// 生成指定大小的新随机盐。
        ///</summary>
        ///<param name=“saltSize”>要生成的盐的大小，以字节为单位。</param>
        ///<returns>指定大小的新随机盐。</returns>
        ///salt的大小必须至少为8字节。</exception>
        internal static byte[] GenerateSalt(int saltSize)
        {
            if (saltSize < 8)
                throw new ArgumentException("salt的长度必须至少为8字节。", "saltSize");

            byte[] salt = new byte[saltSize];
            StaticRngCryptoService.GetBytes(salt);
            return salt;
        }

        #endregion
    }
}
