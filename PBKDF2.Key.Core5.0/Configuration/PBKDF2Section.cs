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

namespace PBKDF2.Key.Security
{
    /// <summary>
    /// 表示配置文件中的PBKDF2配置节。
    /// </summary>
    public sealed class PBKDF2Section : ConfigurationSection
    {
        #region fields

        internal const string XmlTag = "pbkdf2";

        private static readonly object _lock = new object();
        private static readonly ConfigurationProperty _hashName = new ConfigurationProperty("hashName", typeof(string), "HMACSHA256",
            null, PropertyHelper.HashNameValidator, ConfigurationPropertyOptions.None);
        private static readonly ConfigurationProperty _iterationCount = new ConfigurationProperty("iterations", typeof(int), 1000,
            null, PropertyHelper.IterationCountValidator, ConfigurationPropertyOptions.None);
        private static readonly ConfigurationProperty _saltSize = new ConfigurationProperty("saltSize", typeof(int), 8,
            null, PropertyHelper.SaltSizeValidator, ConfigurationPropertyOptions.None);

        private static PBKDF2Section _instance = null;
        private static ConfigurationPropertyCollection _properties;

        #endregion

        #region constructors

        static PBKDF2Section()
        {
            _properties = new ConfigurationPropertyCollection();
            _properties.Add(_hashName);
            _properties.Add(_iterationCount);
            _properties.Add(_saltSize);
        }

        /// <summary>
        /// 创建并初始化System.Security.Cryptography.PBKDF2Section的新实例。
        /// </summary>
        public PBKDF2Section() : base() { }

        #endregion

        #region properties

        /// <summary>
        /// 获取配置文件中的当前System.Configuration.pbkdf2节。如果未在配置文件中定义，则返回初始化为默认值的实例。
        /// </summary>
        public static PBKDF2Section Current
        {
            get
            {
                if (_instance == null)
                    lock (_lock)
                    {
                        if (_instance == null)
                            try
                            {
                                _instance = (PBKDF2Section)ConfigurationManager.GetSection(XmlTag);
                            }
                            catch (Exception)
                            {
                                _instance = new PBKDF2Section();
                            }
                        if (_instance == null)
                            _instance = new PBKDF2Section();
                    }
                return _instance;
            }
        }

        ///<summary>
        ///获取或设置System.Security.Cryptography.PBKDF2类在未指定类型时用于派生密钥的默认哈希名称。
        ///</summary>
        ///<rements>如果配置文件中未指定值，则默认为“HMACSHA256”。</rements>
        ///<returns>System.Security.Cryptography.PBKDF2用于派生密钥的默认哈希名称。</returns>
        ///<exception cref=“System.ArgumentException”>值为null或空。HashName值不能设置为null或空字符串。</exception>
        [ConfigurationProperty("hashName", DefaultValue = "HMACSHA256")]
        [StringValidator(MinLength = 1)]
        public string HashName
        {
            get { return (string)base[_hashName]; }
            set { base[_hashName] = value; }
        }

        ///<summary>
        ///获取或设置System.Security.Cryptography.PBKDF2类在未指定类型时用于派生密钥的默认哈希名称。
        ///</summary>
        ///<rements>如果配置文件中未指定值，则默认为“HMACSHA256”。</rements>
        ///<returns>System.Security.Cryptography.PBKDF2用于派生密钥的默认哈希名称。</returns>
        ///<exception cref=“System.ArgumentException”>值为null或空。HashName值不能设置为null或空字符串。</exception>
        [ConfigurationProperty("iterationCount", DefaultValue = 1000)]
        [IntegerValidator(MinValue = 1, MaxValue = int.MaxValue)]
        public int IterationCount
        {
            get { return (int)base[_iterationCount]; }
            set { base[_iterationCount] = value; }
        }

        ///<summary>
        ///获取或设置System.Security.Cryptography.PBKDF2类在未指定类型时用于派生密钥的默认哈希名称。
        ///</summary>
        ///<rements>如果配置文件中未指定值，则默认为“HMACSHA256”。</rements>
        ///<returns>System.Security.Cryptography.PBKDF2用于派生密钥的默认哈希名称。</returns>
        ///<exception cref=“System.ArgumentException”>值为null或空。HashName值不能设置为null或空字符串。</exception>
        [ConfigurationProperty("saltSize", DefaultValue = 8)]
        [IntegerValidator(MinValue = 8, MaxValue = 65536)]
        public int SaltSize
        {
            get { return (int)base[_saltSize]; }
            set { base[_saltSize] = value; }
        }

        ///<summary>
        ///获取属性的集合。
        ///</summary>
        ///<returns>元素属性的System.Configuration.configurationProperty集合。</returns>
        protected override ConfigurationPropertyCollection Properties
        {
            get { return _properties; }
        }

        #endregion
    }
}
