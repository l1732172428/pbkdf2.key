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
using System.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace PBKDF2.Key.Security
{
    ///<summary>
    ///通过使用基于所选系统的伪随机数生成，实现基于密码的自适应密钥派生功能SCrypt。Security.Cryptography.HMAC派生哈希实现。
    ///</summary>
    public sealed class SCrypt : DeriveBytes
    {
        #region fields

        private static PBKDF2Section _settings = null;

        private uint _block;
        private int _blockSize;
        private byte[] _buffer;
        private int _endIndex;
        private string _hashName;
        private HMAC _hmac;
        private uint _iterationCount;
        private byte[] _password;
        private byte[] _salt;
        private int _startIndex;
        private int _state;

        #endregion

        #region constructors

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(byte[] password, byte[] salt, int iterations, string hashName)
        {
            if (password == null)
                throw new ArgumentNullException("password");
            if (salt == null)
                throw new ArgumentNullException("salt");
            if (string.IsNullOrWhiteSpace(hashName))
                throw new ArgumentNullException("hashName");
            if (salt.Length < 8)
                throw new ArgumentException("参数的长度必须至少为8字节。", "salt");
            if (iterations < 1)
                throw new ArgumentException("参数必须大于零。", "iterations");

            _password = (byte[])password.Clone();
            _salt = (byte[])salt.Clone();
            _hashName = hashName;
            _iterationCount = (uint)iterations;
            Initialize();
        }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(string password, byte[] salt, int iterations, string hashName)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException("password");
            if (salt == null)
                throw new ArgumentNullException("salt");
            if (string.IsNullOrWhiteSpace(hashName))
                throw new ArgumentNullException("hashName");
            if (salt.Length < 8)
                throw new ArgumentException("参数的长度必须至少为8字节。", "salt");
            if (iterations < 1)
                throw new ArgumentException("参数必须大于零。", "iterations");

            _password = new UTF8Encoding(false).GetBytes(password);
            _salt = (byte[])salt.Clone();
            _hashName = hashName;
            _iterationCount = (uint)iterations;
            Initialize();
        }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(byte[] password, int saltSize, int iterations, string hashName)
        {
            if (password == null)
                throw new ArgumentNullException("password");
            if (string.IsNullOrWhiteSpace(hashName))
                throw new ArgumentNullException("hashName");
            if (saltSize < 8)
                throw new ArgumentOutOfRangeException("saltSize", "参数不能小于8。");
            if (iterations < 1)
                throw new ArgumentException("参数必须大于零。", "iterations");

            _password = (byte[])password.Clone();
            _salt = Utils.GenerateSalt(saltSize);
            _hashName = hashName;
            _iterationCount = (uint)iterations;
            Initialize();
        }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(string password, int saltSize, int iterations, string hashName)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException("password");
            if (string.IsNullOrWhiteSpace(hashName))
                throw new ArgumentNullException("hashName");
            if (saltSize < 8)
                throw new ArgumentOutOfRangeException("saltSize", "参数不能小于8。");
            if (iterations < 1)
                throw new ArgumentException("参数必须大于零。", "iterations");

            _password = new UTF8Encoding(false).GetBytes(password);
            _salt = Utils.GenerateSalt(saltSize);
            _hashName = hashName;
            _iterationCount = (uint)iterations;
            Initialize();
        }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(byte[] password, byte[] salt, int iterations) : this(password, salt, iterations, Settings.HashName) { }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(string password, byte[] salt, int iterations) : this(password, salt, iterations, Settings.HashName) { }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(byte[] password, int saltSize, int iterations) : this(password, saltSize, iterations, Settings.HashName) { }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(string password, int saltSize, int iterations) : this(password, saltSize, iterations, Settings.HashName) { }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(byte[] password, byte[] salt) : this(password, salt, Settings.IterationCount, Settings.HashName) { }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“salt”>用于派生密钥的salt。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(string password, byte[] salt) : this(password, salt, Settings.IterationCount, Settings.HashName) { }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(byte[] password, int saltSize) : this(password, saltSize, Settings.IterationCount, Settings.HashName){ }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        ///<param name=“saltSize”>用于派生密钥的salt大小。</param>
        ///<param name=“iterations”>用于派生密钥的迭代次数。</param>
        ///<param name=“hashName”>用于派生密钥的System.Security.Cryptography.HMAC实现的名称。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(string password, int saltSize) : this(password, saltSize, Settings.IterationCount, Settings.HashName) { }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(byte[] password) : this(password, Settings.SaltSize, Settings.IterationCount, Settings.HashName) { }

        /// <summary>
        ///使用密码、salt、迭代次数和System.Security.Cryptography.HMAC哈希实现的名称初始化System.Security.Cryptography.SCrypt类的新实例以派生密钥。
        /// </summary>
        ///<param name=“password”>为其派生密钥的密码。</param>
        /// <exception cref="System.ArgumentNullException">密码、salt或算法为空。</exception>
        /// <exception cref="System.ArgumentException">盐大小小于8或迭代次数小于1。</exception>
        public SCrypt(string password): this(password, Settings.SaltSize, Settings.IterationCount, Settings.HashName){ }

        #endregion

        #region properties

        /// <summary>
        /// 获取或设置派生密钥时要使用的哈希算法的名称。
        /// </summary>
        /// <returns>用于派生密钥的System.Security.Cryptography.HMAC哈希实现的名称。</returns>
        /// <exception cref="System.InvalidOperationException">一旦操作开始，就不能更改值。</exception>
        /// <exception cref="System.ArgumentNullException">值不能为null、空或仅由空白字符组成。</exception>
        public string HashName
        {
            get { return _hashName ?? Settings.HashName; }
            set
            {
                if (_state != 0)
                    throw new InvalidOperationException("HashName 一旦操作开始，就不能更改值。");
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentNullException("value");
                _hashName = value;
                Initialize();
            }
        }

        /// <summary>
        /// 获取或设置派生键时要使用的迭代次数。
        /// </summary>
        /// <returns>用于导出密钥的迭代次数。</returns>
        /// <exception cref="System.InvalidOperationException">一旦操作开始，就不能更改值。</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">值必须大于零。</exception>
        public int IterationCount
        {
            get { return (int)_iterationCount; }
            set
            {
                if (_state != 0)
                    throw new InvalidOperationException("IterationCount 一旦操作开始，就不能更改值。");
                if (value < 1)
                    throw new ArgumentOutOfRangeException("value", "值必须大于零。");
                _iterationCount = (uint)value;
                Initialize();
            }
        }

        /// <summary>
        ///获取或设置派生密钥时要使用的密码。
        /// </summary>
        /// <returns>The password used to derive the key.</returns>
        /// <exception cref="System.InvalidOperationException">一旦操作开始，就不能更改值。</exception>
        /// <exception cref="System.ArgumentNullException">值不能为null。</exception>
        /// <exception cref="System.ArgumentException">值的长度必须至少为1字节。</exception>
        public byte[] Password
        {
            get { return (byte[])_password.Clone(); }
            set
            {
                if (_state != 0)
                    throw new InvalidOperationException("一旦操作开始，密码值就无法更改。");
                if (value == null)
                    throw new ArgumentNullException("value");
                if (value.Length < 1)
                    throw new ArgumentException("值必须是长度至少为1字节的字节数组。", "value");
                _password = (byte[])value.Clone();
                Initialize();
            }
        }

        /// <summary>
        ///获取或设置派生密钥时要使用的salt。
        /// </summary>
        /// <returns>用来推导钥匙的盐。</returns>
        /// <exception cref="System.InvalidOperationException">一旦操作开始，就不能更改值。</exception>
        /// <exception cref="System.ArgumentNullException">值不能为null。</exception>
        /// <exception cref="System.ArgumentException">值的长度必须至少为8字节。</exception>
        public byte[] Salt
        {
            get { return (byte[])_salt.Clone(); }
            set
            {
                if (_state != 0)
                    throw new InvalidOperationException("一旦操作开始，盐值就不能更改。");
                if (value == null)
                    throw new ArgumentNullException("value");
                if (value.Length < 8)
                    throw new ArgumentException("值必须是长度至少为8字节的字节数组。", "value");
                _salt = (byte[])value.Clone();
                Initialize();
            }
        }

        //获取默认值的配置设置的静态副本。
        internal static PBKDF2Section Settings
        {
            get
            {
                if (_settings == null)
                    _settings = PBKDF2Section.Current;
                return _settings;
            }
        }

        #endregion

        #region methods

        /// <summary>
        ///释放Syste.Security.Cryptography.SCrypt类使用的非托管资源，并可以选择释放托管资源。
        /// </summary>
        /// <param name="disposing">true以释放托管和非托管资源；如果为false，则仅释放非托管资源。</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                if (_hmac != null)
                    _hmac.Dispose();
                if (_buffer != null)
                    Array.Clear(_buffer, 0, _buffer.Length);
                if (_password != null)
                    Array.Clear(_password, 0, _password.Length);
                if (_salt != null)
                    Array.Clear(_salt, 0, _salt.Length);
            }
        }

        //迭代散列函数
        private byte[] Func()
        {
            byte[] INT_block = Utils.GetBigEndianBytes(_block);

            _hmac.TransformBlock(_salt, 0, _salt.Length, _salt, 0);
            _hmac.TransformFinalBlock(INT_block, 0, INT_block.Length);
            byte[] temp = _hmac.Hash;
            _hmac.Initialize();

            byte[] ret = temp;
            for (int i = 2; i <= _iterationCount; i++)
            {
                temp = _hmac.ComputeHash(temp);
                for (int j = 0; j < _blockSize; j++)
                {
                    ret[j] ^= temp[j];
                }
            }

            _block++;
            return ret;
        }

        ///<summary>
        ///返回此对象的伪随机字节。
        ///</summary>
        ///<param name=“cb”>要生成的伪随机密钥字节数。</param>
        ///<returns>填充伪随机密钥字节的字节数组。</returns>
        /// <exception cref="System.ArgumentOutOfRangeException">cb必须大于零。</exception>
        /// <exception cref="System.ArgumentException">内部缓冲区的开始索引或结束索引无效。</exception>
        public override byte[] GetBytes(int cb)
        {
            if (cb <= 0)
                throw new ArgumentOutOfRangeException("cb", "参数必须是大于零的值。");

            _state = 1;

            byte[] key = new byte[cb];
            int offset = 0;
            int size = _endIndex - _startIndex;
            if (size > 0)
            {
                if (cb >= size)
                {
                    Buffer.BlockCopy(_buffer, _startIndex, key, 0, size);
                    _startIndex = _endIndex = 0;
                    offset += size;
                }
                else
                {
                    Buffer.BlockCopy(_buffer, _startIndex, key, 0, cb);
                    _startIndex += cb;
                    return key;
                }
            }

            if (_startIndex != 0 && _endIndex != 0)
                throw new ArgumentException("内部缓冲区中的开始或结束索引无效");

            while (offset < cb)
            {
                byte[] T_block = Func();
                int remainder = cb - offset;
                if (remainder > _blockSize)
                {
                    Buffer.BlockCopy(T_block, 0, key, offset, _blockSize);
                    offset += _blockSize;
                }
                else
                {
                    Buffer.BlockCopy(T_block, 0, key, offset, remainder);
                    offset += remainder;
                    Buffer.BlockCopy(T_block, remainder, _buffer, _startIndex, _blockSize - remainder);
                    _endIndex += (_blockSize - remainder);
                    return key;
                }
            }
            return key;
        }

        //初始化操作的状态。
        private void Initialize()
        {
            if (_buffer != null)
                Array.Clear(_buffer, 0, _buffer.Length);

            _hmac = HMAC.Create(_hashName);
            _hmac.Key = (byte[])_password.Clone();
            _blockSize = _hmac.HashSize / 8;
            _buffer = new byte[_blockSize];
            _block = 1;
            _startIndex = _endIndex = 0;
            _state = 0;
        }

        ///<summary>
        ///重置操作的状态。
        ///</summary>
        public override void Reset()
        {
            Initialize();
        }

        #endregion
    }
}
