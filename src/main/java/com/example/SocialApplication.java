package com.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@EnableOAuth2Client
@EnableAuthorizationServer
@Order(6)
public class SocialApplication extends WebSecurityConfigurerAdapter {


    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    //MongoDB repository
    @Autowired
    LogRepository repository;

    private static final Logger log = LoggerFactory.getLogger(SocialApplication.class);

    @RequestMapping({"/user", "/me"})
    public Map<String, String> user(Principal principal) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("name", principal.getName());
        RestTemplate restTemplate = new RestTemplate();
        GithubUser user = restTemplate.getForObject("https://api.github.com/user?access_token=" + oauth2ClientContext.getAccessToken().getValue(), GithubUser.class);
        map.put("userdata", user.toString());
        return map;
    }


    //Return repositories for authenticated github user
    @RequestMapping({"/repos"})
    public Map<String, Repository[]> repos() {
        Map<String, Repository[]> map = new LinkedHashMap<>();

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Repository[]> responseEntity = restTemplate.getForEntity("https://api.github.com/user/repos?access_token=" + oauth2ClientContext.getAccessToken().getValue(), Repository[].class);
        Repository[] repositories = responseEntity.getBody();

        map.put("repositories", repositories);
        return map;
    }


    //Return logs from mongoDB repository
    @RequestMapping("/logs")
    public Map<String, Object[]> getRecords() {
        Map<String, Object[]> map = new LinkedHashMap<>();
        map.put("logs", repository.findAll().toArray());
        return map;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        LogoutSuccessHandler logoutSuccessHandler = new LogoutSuccessHandler("/");

        //Authorize any requests to /login, /webjars, /logs. For others, require authentication
        http.antMatcher("/**").authorizeRequests()
                .antMatchers("/", "/login**", "/webjars/**", "/logs**").permitAll()
                .anyRequest().authenticated()
                .and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
                .and().logout().logoutSuccessHandler(logoutSuccessHandler).invalidateHttpSession(true).logoutSuccessUrl("/").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

    }



    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }


    //Return github Oauth2 resources from configuration file
    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() {
        return new ClientResources();
    }


    //Default ssoFilter is set to github filter
    private Filter ssoFilter() {
        return ssoFilter(github(), "/login/github");
    }

    private Filter ssoFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter oAuth2ClientAuthenticationFilter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
        oAuth2ClientAuthenticationFilter.setRestTemplate(oAuth2RestTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(client.getResource().getUserInfoUri(),
                client.getClient().getClientId());
        tokenServices.setRestTemplate(oAuth2RestTemplate);
        oAuth2ClientAuthenticationFilter.setTokenServices(tokenServices);
        oAuth2ClientAuthenticationFilter.setAuthenticationSuccessHandler(new AuthorizationSuccessHandler("/"));
        return oAuth2ClientAuthenticationFilter;
    }

    //Custom logoutSuccess handler to log act of logout on successful logout
    private class LogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

        public LogoutSuccessHandler(String defaultTargetURL) {
            this.setDefaultTargetUrl(defaultTargetURL);
        }

        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            repository.save(new LogRecord(authentication.getName(), new Date(), LogRecord.Type.logout));
            super.onLogoutSuccess(request, response, authentication);
        }

    }

    //Custom authorizationSuccess handler to log act of authorization on successful login
    private class AuthorizationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

        public AuthorizationSuccessHandler(String defaultTargetURL) {
            this.setDefaultTargetUrl(defaultTargetURL);
        }

        @Override
        public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
            repository.save(new LogRecord(authentication.getName(), new Date(), LogRecord.Type.login));
            super.onAuthenticationSuccess(httpServletRequest, httpServletResponse, authentication);
        }
    }

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
        }
    }
}


