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

using System.Configuration;

namespace PBKDF2.Key.Security
{
    /// <summary>
    /// 内部实用程序/助手类
    /// </summary>
    internal static class PropertyHelper
    {
        #region fields

        private static ConfigurationValidatorBase _hashNameValidator = null;
        private static ConfigurationValidatorBase _iterationCountValidator = null;
        private static ConfigurationValidatorBase _saltSizeValidator = null;

        #endregion

        #region properties

        /// <summary>
        /// 获取System.Configuration.PBKDF2Section.HashName配置属性值的验证程序。
        /// </summary>
        public static ConfigurationValidatorBase HashNameValidator
        {
            get
            {
                if (_hashNameValidator == null)
                    _hashNameValidator = new StringValidator(1);
                return _hashNameValidator;
            }
        }

        /// <summary>
        /// 获取System.Configuration.PBKDF2Section.IterationCount配置属性值的验证程序。
        /// </summary>
        public static ConfigurationValidatorBase IterationCountValidator
        {
            get
            {
                if (_iterationCountValidator == null)
                    _iterationCountValidator = new IntegerValidator(1, int.MaxValue);
                return _iterationCountValidator;
            }
        }

        /// <summary>
        /// 获取System.Configuration.PBKDF2Section.SaltSize配置属性值的验证程序。
        /// </summary>
        public static ConfigurationValidatorBase SaltSizeValidator
        {
            get
            {
                if (_saltSizeValidator == null)
                    _saltSizeValidator = new IntegerValidator(8, 65536);
                return _saltSizeValidator;
            }
        }

        #endregion
    }
}
