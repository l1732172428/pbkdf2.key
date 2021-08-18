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

namespace PBKDF2.Key.Security
{
    /// <summary>
    /// 不可逆
    /// </summary>
    public class Irreversible
    {
        #region Key byte[]

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(byte[] password, byte[] salt, int iterations, string hashName, int hashSize)
        {
            return new SCrypt(password, salt,iterations,hashName).GetBytes(hashSize);
        }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param> 
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(string password, byte[] salt, int iterations, string hashName, int hashSize) { return new SCrypt(password, salt, iterations, hashName).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(byte[] password, int saltSize, int iterations, string hashName, int hashSize) { return new SCrypt(password, saltSize, iterations, hashName).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(string password, int saltSize, int iterations, string hashName, int hashSize) { return new SCrypt(password, saltSize, iterations, hashName).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(byte[] password, byte[] salt, int iterations, int hashSize) { return new SCrypt(password, salt, iterations).GetBytes(hashSize); }
        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(string password, byte[] salt, int iterations, int hashSize) { return new SCrypt(password, salt, iterations).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(byte[] password, int saltSize, int iterations, int hashSize) { return new SCrypt(password, saltSize, iterations).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(string password, int saltSize, int iterations, int hashSize) { return new SCrypt(password, saltSize, iterations).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(byte[] password, byte[] salt, int hashSize) { return new SCrypt(password, salt).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(string password, byte[] salt, int hashSize) { return new SCrypt(password, salt).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(byte[] password, int saltSize, int hashSize) { return new SCrypt(password, saltSize).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(string password, int saltSize, int hashSize) { return new SCrypt(password, saltSize).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(byte[] password, int hashSize) { return new SCrypt(password).GetBytes(hashSize); }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        /// <param name="hashSize">字节大小</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public byte[] Encrypted(string password, int hashSize) { return new SCrypt(password).GetBytes(hashSize); }

        #endregion

    }
}
