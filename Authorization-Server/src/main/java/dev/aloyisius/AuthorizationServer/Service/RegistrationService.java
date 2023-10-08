package dev.aloyisius.AuthorizationServer.Service;

import dev.aloyisius.AuthorizationServer.Entity.AppUsers;
import dev.aloyisius.AuthorizationServer.Repository.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class RegistrationService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;


    public RegistrationService(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;

    }

    public void registerUser(AppUsers users){
        appUserRepository.findByEmail(users.getEmail()).ifPresent(x ->{
            throw new RuntimeException();
        });
        users.setPassword(passwordEncoder.encode(users.getPassword()));
        appUserRepository.save(users);
    }
}
