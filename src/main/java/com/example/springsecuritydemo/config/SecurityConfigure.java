package com.example.springsecuritydemo.config;

import com.example.springsecuritydemo.po.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.UrlAuthorizationConfigurer;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Configuration
public class SecurityConfigure extends WebSecurityConfigurerAdapter {

    private final SecurityUserDetailsService securityUserDetailsService;

    private final DataSource dataSource;

    private final DemoSecurityMetadataSource demoSecurityMetadataSource;

    @Autowired
    public SecurityConfigure(SecurityUserDetailsService securityUserDetailsService, DataSource dataSource, DemoSecurityMetadataSource demoSecurityMetadataSource) {
        this.securityUserDetailsService = securityUserDetailsService;
        this.dataSource = dataSource;
        this.demoSecurityMetadataSource = demoSecurityMetadataSource;
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(securityUserDetailsService);
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public DemoAuthenticationFilter authenticationFilter() throws Exception {
        DemoAuthenticationFilter demoAuthenticationFilter = new DemoAuthenticationFilter();

        demoAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        demoAuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "success");
            User principal = (User) authentication.getPrincipal();
            result.put("userInfo", principal);

            response.setStatus(HttpStatus.OK.value());
            response.setContentType("application/json;charset=UTF-8");

            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        });

        demoAuthenticationFilter.setAuthenticationFailureHandler((request, response, exception) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "failed");
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setContentType("application/json;charset=UTF-8");

            String s = new ObjectMapper().writeValueAsString(result);

            response.getWriter().println(s);
        });

        demoAuthenticationFilter.setRememberMeServices(rememberMeServices());
        return demoAuthenticationFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        http.apply(new UrlAuthorizationConfigurer<>(applicationContext))
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setSecurityMetadataSource(demoSecurityMetadataSource);
                        object.setRejectPublicInvocations(false);
                        return object;
                    }
                });


        http.authorizeHttpRequests()
                .anyRequest().authenticated()
                .and().formLogin()
                .and()
                .rememberMe()
                .rememberMeServices(rememberMeServices())
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getOutputStream().println("unauthorized");
                })
                .and()
                .logout()
                .logoutSuccessHandler((request, response, authentication) -> {
                    Map<String, Object> result = new HashMap<>();
                    result.put("msg", "success");
                    response.setStatus(HttpStatus.OK.value());
                    response.setContentType("application/json;charset=UTF-8");

                    String s = new ObjectMapper().writeValueAsString(result);

                    response.getOutputStream().println(s);
                })
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                ;


        http.addFilterAt(authenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public RememberMeServices rememberMeServices() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();

        jdbcTokenRepository.setCreateTableOnStartup(false);
        jdbcTokenRepository.setDataSource(dataSource);
        return new DemoRememberService(UUID.randomUUID().toString(), userDetailsService(), jdbcTokenRepository);
    }

}
