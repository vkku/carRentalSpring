package config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;
import config.CustomLogoutSuccessHandler;
import config.CustomAccessDeniedHandler;
import config.CustomAuthenticationFailureHandler;


@Configuration
@EnableWebSecurity
@EnableWebMvc
@ImportResource({ "classpath:webSecurityConfig.xml" })
public class SecSecurityConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

	public SecSecurityConfig() {
		super();
	}
 
    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
    	auth.inMemoryAuthentication()
        .withUser("user").password(passwordEncoder().encode("user")).roles("USER")
        .and()
        .withUser("vendor").password(passwordEncoder().encode("vendor")).roles("VENDOR")
        .and()
        .withUser("admin").password(passwordEncoder().encode("admin")).roles("ADMIN");
}
 
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
    	 http
         .csrf().disable()
         .authorizeRequests()
         .antMatchers("/admin/**").hasRole("ADMIN")
         .antMatchers("/anonymous*").anonymous()
         .antMatchers("/login*").permitAll()
         .anyRequest().authenticated()
         .and()
         .formLogin()
         .loginPage("/login.html")
         .loginProcessingUrl("/perform_login")
         .defaultSuccessUrl("/homepage.html", true)
         .failureUrl("/login.html?error=true")
         .failureHandler(authenticationFailureHandler())
         .and()
         .logout()
         .logoutUrl("/perform_logout")
         .deleteCookies("JSESSIONID")
         .logoutSuccessHandler(logoutSuccessHandler());
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new CustomLogoutSuccessHandler();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }


    @Bean 
    public PasswordEncoder passwordEncoder() { 
        return new BCryptPasswordEncoder(); 
    }

    @Override
    public void addViewControllers(final ViewControllerRegistry registry) {

        registry.addViewController("/anonymous.html");
        registry.addViewController("/login.html");
        registry.addViewController("/homepage.html");
        registry.addViewController("/admin/adminpage.html");
        registry.addViewController("/accessDenied");
    }

    @Bean
    public ViewResolver viewResolver() {
        final InternalResourceViewResolver bean = new InternalResourceViewResolver();

        bean.setViewClass(JstlView.class);
        bean.setPrefix("/WEB-INF/view/");
        bean.setSuffix(".jsp");

        return bean;
    }
}