package dev.aloyisius.AuthorizationServer.Security;

import dev.aloyisius.AuthorizationServer.Entity.AppUsers;
import dev.aloyisius.AuthorizationServer.Repository.AppUserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository repository;

    public AppUserDetailsService(AppUserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByEmail(username)
                .map(AppUserDetail::new)
                .orElseThrow(()-> new UsernameNotFoundException("User with username: %s not found".formatted(username)));
    }

    protected static class AppUserDetail extends AppUsers implements UserDetails {
        public AppUserDetail(AppUsers users) {
            super(users);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of(()-> "USER");
        }

        @Override
        public String getUsername() {
            return this.getEmail();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
