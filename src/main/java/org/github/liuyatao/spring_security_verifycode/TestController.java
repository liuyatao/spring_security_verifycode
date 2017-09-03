package org.github.liuyatao.spring_security_verifycode;


import com.google.code.kaptcha.Constants;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@Controller
public class TestController {


    private Logger logger=Logger.getLogger(TestController.class.getName());

    private DefaultKaptcha captchaProducer;

    public TestController(DefaultKaptcha kaptcha) {
        this.captchaProducer=kaptcha;
    }

    @RequestMapping(value = "/")
    @ResponseBody
    public ModelAndView index(Principal principal){
        Map helloMap=new HashMap();
        helloMap.put("msg","Hello "+principal.getName());
        return new ModelAndView("index",helloMap);
    }

    @RequestMapping(value = "/login")
    public String login(){
        return "login";
    }



    /**
     * 生成验证码
     */
    @RequestMapping(value = "/randCode")
    public void getRandCode(HttpServletRequest request, HttpServletResponse response){

        HttpSession session = request.getSession();


        response.setDateHeader("Expires", 0);

        // Set standard HTTP/1.1 no-cache headers.
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

        // Set IE extended HTTP/1.1 no-cache headers (use addHeader).
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");

        // Set standard HTTP/1.0 no-cache header.
        response.setHeader("Pragma", "no-cache");

        // 设置返回文件类型
        response.setContentType("image/jpeg");

        // 获取验证码上的文字
        String capText = captchaProducer.createText();

        // 将验证码上的文字保存在session中
        session.setAttribute(Constants.KAPTCHA_SESSION_KEY, capText);

        String code = (String)session.getAttribute(Constants.KAPTCHA_SESSION_KEY);

        logger.info("验证码为:"+code);

        //  将文件渲染到图片上
        BufferedImage bi = captchaProducer.createImage(capText);
        ServletOutputStream out = null;
        try {
            out = response.getOutputStream();
            ImageIO.write(bi, "jpeg", out);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }finally {

        }


    }
}
