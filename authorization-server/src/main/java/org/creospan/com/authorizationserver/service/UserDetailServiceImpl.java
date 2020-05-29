package org.creospan.com.authorizationserver.service;

import org.creospan.com.authorizationserver.model.AuthUserDetail;
import org.creospan.com.authorizationserver.model.User;
import org.creospan.com.authorizationserver.repository.UserDetailRepository;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service("userDetailsService")
public class UserDetailServiceImpl implements UserDetailsService {
    private final UserDetailRepository userDetailRepository;

    public UserDetailServiceImpl(UserDetailRepository userDetailRepository) {
        this.userDetailRepository = userDetailRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userDetailRepository.findByUsername( username );
        user.orElseThrow( () -> new UsernameNotFoundException( "Username or password not found" ) );
        UserDetails userDetails = new AuthUserDetail( user.get() );
        new AccountStatusUserDetailsChecker() // to check if the userAccount is expired, is valid or not
                .check( userDetails );
        return userDetails;
    }
}
