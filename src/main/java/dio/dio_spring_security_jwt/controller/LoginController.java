package dio.dio_spring_security_jwt.controller;

import dio.dio_spring_security_jwt.dtos.Login;
import dio.dio_spring_security_jwt.dtos.Sessao;
import dio.dio_spring_security_jwt.model.User;
import dio.dio_spring_security_jwt.repository.UserRepository;
import dio.dio_spring_security_jwt.security.JWTCreator;
import dio.dio_spring_security_jwt.security.JWTObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.util.Date;

@RestController
public class LoginController {

    private final PasswordEncoder encoder;
    private final UserRepository repository;

    private final String jwtPrefix;
    private final String jwtKey;
    private final Long jwtExpiration;

    public LoginController(
            PasswordEncoder encoder,
            UserRepository repository,
            @Value("${security.config.prefix}") String jwtPrefix,
            @Value("${security.config.key}") String jwtKey,
            @Value("${security.config.expiration}") Long jwtExpiration) {
        this.encoder = encoder;
        this.repository = repository;
        this.jwtPrefix = jwtPrefix;
        this.jwtKey = jwtKey;
        this.jwtExpiration = jwtExpiration;
    }

    @PostMapping("/login")
    public Sessao logar(@RequestBody Login login) {
        User user = repository.findByUsername(login.getUsername());

        if (user == null || !encoder.matches(login.getPassword(), user.getPassword())) {
            // Lógica mais clara: se o usuário não for encontrado OU a senha for inválida, lança a exceção.
            throw new RuntimeException("Usuário ou senha inválidos.");
        }


        JWTObject jwtObject = new JWTObject();
        jwtObject.setIssuedAt(new Date(System.currentTimeMillis()));
        jwtObject.setExpiration(new Date(System.currentTimeMillis() + jwtExpiration));
        jwtObject.setRoles(user.getRoles());

        Sessao sessao = new Sessao();
        sessao.setLogin(user.getUsername());
        sessao.setToken(JWTCreator.create(jwtPrefix, jwtKey, jwtObject));

        return sessao;
    }
}