package org.github.liuyatao.spring_security_verifycode;

import com.google.code.kaptcha.Constants;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.logging.Logger;

/**
 * 继承 UsernamePasswordAuthenticationFilter 实现自定义登录
 * 使用LoginAuthenticationFilter替换原有的用户名密码认证凡是，需要删除http.formLogin，因为http.formLogin会创建一个LoginAuthenticationFilter
 */
public class LoginAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static  final Logger logger=Logger.getLogger(LoginAuthenticationFilter.class.getName());

    public LoginAuthenticationFilter() {
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //获取表单提交的验证码的值
        String verification = request.getParameter("code");
        //获取下发的存在session中的验证码的值
        String captcha = (String) request.getSession().getAttribute(Constants.KAPTCHA_SESSION_KEY);

        if (captcha==null){
            throw new CaptchaException("验证码不为空");
        }
        else  if (!captcha.contentEquals(verification)) {
            throw new CaptchaException("验证码不匹配");
        }
        //调用UsernamePasswordAuthenticationFilter的认证方法
        return super.attemptAuthentication(request, response);
    }
}
