package dev.aloyisius.AuthorizationServer;

import dev.aloyisius.AuthorizationServer.Entity.AppUsers;
import dev.aloyisius.AuthorizationServer.Service.RegistrationService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class AuthorizationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner(RegistrationService registrationService){
		return args -> {
			AppUsers user = new AppUsers();
			user.setEmail("anthon11@auth.com");
			user.setPassword("123456");
			user.setFirstName("Anthony");
			user.setLastName("Joshua");

			registrationService.registerUser(user);
		};
	}
}
