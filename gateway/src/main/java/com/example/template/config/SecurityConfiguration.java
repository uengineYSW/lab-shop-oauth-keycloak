package com.example.template.config;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.*;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class SecurityConfiguration extends KeycloakWebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.authorizeRequests()

        .antMatchers("/orders/**").hasAnyRole("CUSTOMER").anyRequest()
        .permitAll();
        http.csrf().disable();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    public KeycloakConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }
}


// package com.example.template.config;

// import java.util.Collection;
// import java.util.List;
// import java.util.Map;
// import java.util.stream.Collectors;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.core.convert.converter.Converter;
// import org.springframework.security.authentication.AbstractAuthenticationToken;
// import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
// import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
// import org.springframework.security.config.web.server.ServerHttpSecurity;
// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.authority.SimpleGrantedAuthority;
// import org.springframework.security.oauth2.jwt.Jwt;
// import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
// import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.server.SecurityWebFilterChain;
// import reactor.core.publisher.Mono;

// @Configuration
// @EnableWebFluxSecurity
// @EnableGlobalMethodSecurity(jsr250Enabled = true)
// public class SecurityConfiguration {

//     @Bean
//     SecurityFilterChain springSecurityFilterChain(HttpSecurity http)
//         throws Exception {
//         http.csrf().disable();
//         http.authorizeRequests()
//             .requestMatchers("/user/**").authenticated()
//             .requestMatchers("/orders/**").hasRole("CUSTOMER")
//             .anyRequest()
//             .permitAll();
            
//         http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//         return http.build();
//     }

//     Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
//         JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
//         jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
//             new GrantedAuthoritiesExtractor()
//         );

//         return new ReactiveJwtAuthenticationConverterAdapter(
//             jwtAuthenticationConverter
//         );
//     }

//     static class GrantedAuthoritiesExtractor
//         implements Converter<Jwt, Collection<GrantedAuthority>> {

//         public Collection<GrantedAuthority> convert(Jwt jwt) {
//             final Map<String, List<String>> realmAccess = (Map<String, List<String>>) jwt
//                 .getClaims()
//                 .get("realm_access");

//             return realmAccess
//                 .get("roles")
//                 .stream()
//                 .map(roleName -> "ROLE_" + roleName)
//                 .map(SimpleGrantedAuthority::new)
//                 .collect(Collectors.toList());
//         }
//     }
// }
