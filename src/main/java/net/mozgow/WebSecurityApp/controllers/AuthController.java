package net.mozgow.WebSecurityApp.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import net.mozgow.WebSecurityApp.Service.UserDetailsImpl;
import net.mozgow.WebSecurityApp.configs.jwt.JwtUtils;
import net.mozgow.WebSecurityApp.models.ERole;
import net.mozgow.WebSecurityApp.models.Role;
import net.mozgow.WebSecurityApp.models.User;
import net.mozgow.WebSecurityApp.pojo.JwtResponse;
import net.mozgow.WebSecurityApp.pojo.LoginRequest;
import net.mozgow.WebSecurityApp.pojo.MessageResponse;
import net.mozgow.WebSecurityApp.pojo.SignupRequest;
import net.mozgow.WebSecurityApp.repository.RoleRepository;
import net.mozgow.WebSecurityApp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
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

    //аутотентификация пользователя
    @PostMapping("/signin")
    public ResponseEntity<?> authUser(@RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    //регистрация пользователя
    @PostMapping("/signup")
    public ResponseEntity<?> registerUsers(@RequestBody SignupRequest signupRequest) {

        //проверка совпадений имени в БД
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Ошибка: Пользователь с таким именем уже существует"));
        }

        //проверка совпадений почты в БД
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Ошибка: пользователь с такой почтой уже существует"));
        }


        //если проверка на уникальность прошла, то отвправляем Set<Role> в БД
        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                passwordEncoder.encode(signupRequest.getPassword()));

        Set<String> reqRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        //прверяем наличие роли в записи
        if (reqRoles == null) {
            Role userRole = roleRepository
                    .findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Ошибка: Роль не найдена"));
            roles.add(userRole);
        } else {
            reqRoles.forEach(r -> {
                switch (r) {
                    case "admin":
                        Role adminRole = roleRepository
                                .findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Ошибка: Роль ADMINISTRATOR не найдена"));
                        roles.add(adminRole);

                        break;

                    default:
                        Role userRole = roleRepository
                                .findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Ошибка: Роль USER не найдена"));
                        roles.add(userRole);
                }
            });
        }

        //записываем роль и юзера в БД
        user.setRole(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Пользователь создан"));
    }
}
