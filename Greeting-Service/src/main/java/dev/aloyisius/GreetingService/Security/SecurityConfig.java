package dev.aloyisius.GreetingService.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(auth -> {
            auth.anyRequest().authenticated();
        });
        httpSecurity.oauth2Login(Customizer.withDefaults());
        return httpSecurity.build();

    }
    @Bean
    public ClientRegistrationRepository registrationRepository(){

        return new InMemoryClientRegistrationRepository(clientRegistration());
    }

    private ClientRegistration clientRegistration(){
        return ClientRegistration.withRegistrationId("authorization-service")

                .clientId("greeting-service-app")
                .clientSecret("secret4greeting")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(OidcScopes.OPENID, "user.read", "user.write")
                .authorizationUri("http://localhost:8080/oauth2/authorize")
                .userInfoUri("http://localhost:8080/userinfo")
                .tokenUri("http://localhost:8080/oauth2/token")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .issuerUri("http://localhost:8080")
                .jwkSetUri("http://localhost:8080/oauth2/jwks")
                .build();
    }


}
