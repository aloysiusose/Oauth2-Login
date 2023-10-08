package dev.aloyisius.AuthorizationServer.Controller;

import dev.aloyisius.AuthorizationServer.Entity.AppUsers;
import dev.aloyisius.AuthorizationServer.Service.RegistrationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/register")
public class RegistrationController {

    private final RegistrationService registrationService;

    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping("/user")
    public void registerUser(@RequestBody AppUsers users){
        registrationService.registerUser(users);
    }

    @PostMapping("/client")
    public void registerClient(){}

    @ExceptionHandler
    public ResponseEntity<?> handleException(Exception ex){
        return ResponseEntity.badRequest().body(ex.getMessage());
    }
}
