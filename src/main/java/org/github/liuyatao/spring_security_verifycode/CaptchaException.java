package org.github.liuyatao.spring_security_verifycode;

import org.springframework.security.authentication.AuthenticationServiceException;


/**
 * 验证码填写异常
 */
public class CaptchaException extends AuthenticationServiceException {
    public CaptchaException(String msg) {
        super(msg);
    }
}
