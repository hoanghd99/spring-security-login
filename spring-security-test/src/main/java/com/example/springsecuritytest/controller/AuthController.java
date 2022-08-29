package com.example.springsecuritytest.controller;

import com.example.springsecuritytest.entity.ERole;
import com.example.springsecuritytest.entity.Role;
import com.example.springsecuritytest.entity.User;
import com.example.springsecuritytest.payload.request.LoginRequest;
import com.example.springsecuritytest.payload.request.SignupRequest;
import com.example.springsecuritytest.payload.response.MessageResponse;
import com.example.springsecuritytest.payload.response.UserInfoResponse;
import com.example.springsecuritytest.repository.RoleRepository;
import com.example.springsecuritytest.repository.UserRepository;
import com.example.springsecuritytest.security.jwt.JwtUtils;
import com.example.springsecuritytest.security.service.UserDetailsImpl;
import com.example.springsecuritytest.security.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.orm.hibernate5.HibernateTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                                        .map(item -> item.getAuthority())
                                        .collect(Collectors.toList());

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                                  .body(new UserInfoResponse(userDetails.getId(),
                                                             userDetails.getUsername(),
                                                             userDetails.getEmail(),
                                                             roles));

    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {

        if (userRepository.existsByUsername(signupRequest.getUsername()))
        {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username da ton tai"));
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email da ton tai"));
        }

        // Create new user account
        User user = new User(signupRequest.getUsername(),
                             signupRequest.getEmail(),
                             passwordEncoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found"));

            roles.add(userRole);
        }

        else {
            strRoles.forEach(
                    role -> {
                        switch (role) {
                            case "admin":
                                Role admin = roleRepository.findByName(ERole.ROLE_ADMIN)
                                                            .orElseThrow(() -> new RuntimeException("Error: Role is not found"));

                                roles.add(admin);
                                break;
                            case "mod":
                                Role mod = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                                         .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                                roles.add(mod);
                                break;
                            default:
                                Role roleUser = roleRepository.findByName(ERole.ROLE_USER)
                                                              .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                                roles.add(roleUser);

                        }
                    }
            );
        }

        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User Registered Successfully"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {

        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                            .body(new MessageResponse("You have been signed out"));

    }
}
































