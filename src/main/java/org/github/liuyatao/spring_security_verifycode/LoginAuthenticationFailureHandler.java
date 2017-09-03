package org.github.liuyatao.spring_security_verifycode;

public class LoginAuthenticationFailureHandler {
    public static final String CODE_ERROR_URL = "http://localhost:8083/login?code_error";
    public static final String EXPIRED_URL = "http://localhost:8083/login?expired";
    public static final String LOCKED_URL = "http://localhost:8083/login?locked";
    public static final String DISABLED_URL = "http://localhost:8083/login?disabled";

    public static final String PASS_ERROR_URL = "http://localhost:8083/login?pass_error";

    public LoginAuthenticationFailureHandler() {
    }


}
