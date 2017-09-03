package org.github.liuyatao.spring_security_verifycode;

import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


/**
 * spring security 核心配置
 */
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                    .addFilterBefore(loginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                    .exceptionHandling()
                        .authenticationEntryPoint(loginUrlAuthenticationEntryPoint())  //使用新的登录EntryPoint
                .and()
                    .authorizeRequests()
                        .antMatchers("/login","/authentication","/randCode").permitAll() //可以直接访问
                        .anyRequest().authenticated() //任何请求都必须经过授权
                .and()
                    .logout()
                        .clearAuthentication(true)
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                        .invalidateHttpSession(true);
                       // .logoutSuccessUrl("/login?logout"); //默认为/login?logout

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.debug(true).ignoring().antMatchers("/js/*.js","/css/*.css","/fonts/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("admin")
                .roles("ADMINN")
             .and()
                .withUser("user")
                .password("user")
                .roles("USER");
    }

    /**
     * 需要显示声明该Bean
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    /*声明LoginAuthenticationFilter Bean*/
    @Bean
    public LoginAuthenticationFilter loginAuthenticationFilter() throws Exception {
        LoginAuthenticationFilter loginAuthenticationFilter=new LoginAuthenticationFilter();
        loginAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        loginAuthenticationFilter.setFilterProcessesUrl("/authentication");
        loginAuthenticationFilter.setAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
        loginAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return loginAuthenticationFilter;
    }

    /*声明登录endpoint Bean*/
    @Bean
    public LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint(){
        LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint=new LoginUrlAuthenticationEntryPoint("/login");
        return loginUrlAuthenticationEntryPoint;
    }



    /*声明授权失败异常处理 Bean*/
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        //根据抛出的不同的异常跳转到不同的URL
        ExceptionMappingAuthenticationFailureHandler failureHandler = new ExceptionMappingAuthenticationFailureHandler();
        Map<String, String> failureUrlMap = new HashMap<>();
        failureUrlMap.put(BadCredentialsException.class.getName(), LoginAuthenticationFailureHandler.PASS_ERROR_URL);
        failureUrlMap.put(CaptchaException.class.getName(), LoginAuthenticationFailureHandler.CODE_ERROR_URL);
        failureUrlMap.put(AccountExpiredException.class.getName(), LoginAuthenticationFailureHandler.EXPIRED_URL);
        failureUrlMap.put(LockedException.class.getName(), LoginAuthenticationFailureHandler.LOCKED_URL);
        failureUrlMap.put(DisabledException.class.getName(), LoginAuthenticationFailureHandler.DISABLED_URL);
        failureHandler.setExceptionMappings(failureUrlMap);
        return failureHandler;
    }


    /*声明验证码生成策略属性 Bean*/
    @Bean
    public DefaultKaptcha captchaProducer(){
        DefaultKaptcha captchaProducer =new DefaultKaptcha();
        Properties properties =new Properties();
        properties.setProperty("kaptcha.border","yes");
        properties.setProperty("kaptcha.border.color","105,179,90");
        properties.setProperty("kaptcha.textproducer.font.color","red");
        properties.setProperty("kaptcha.image.width","125");
        properties.setProperty("kaptcha.image.height","45");
        properties.setProperty("kaptcha.textproducer.font.size","45");
        properties.setProperty("kaptcha.session.key","code");
        properties.setProperty("kaptcha.textproducer.char.length","4");
        properties.setProperty("kaptcha.textproducer.font.names","宋体,楷体,微软雅黑");
        Config config=new Config(properties);
        captchaProducer.setConfig(config);
        return  captchaProducer;
    }
}
