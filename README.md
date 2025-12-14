
# Authentication Server (OAuth 2.0 / OpenID Connect)

Centralized Authentication & Authorization Server for the **UCIAP ecosystem**, built on **Keycloak** and compliant with **OAuth 2.0** and **OpenID Connect (OIDC)** standards.

This server provides secure identity management, token issuance, role-based access control, email verification, and MFA support for all client applications.

---

## 🔐 Features

- OAuth 2.0 Authorization Server (Keycloak)
- OpenID Connect (OIDC) compliant
- Authorization Code + PKCE
- Client Credentials
- Refresh Token flow
- JWT-based access tokens
- Role-based access control (RBAC)
- Email verification on user registration
- Single Sign-On (SSO)
- Single Logout (Front-channel logout)
- Google & Microsoft Authenticator (TOTP MFA)
- Centralized identity for microservices

---

## 🧭 Realm Information

**Realm Name:** `UCIAP`

```json
{
  "issuer": "http://localhost:8080/realms/UCIAP",
  "authorization_endpoint": "http://localhost:8080/realms/UCIAP/protocol/openid-connect/auth",
  "token_endpoint": "http://localhost:8080/realms/UCIAP/protocol/openid-connect/token",
  "introspection_endpoint": "http://localhost:8080/realms/UCIAP/protocol/openid-connect/token/introspect",
  "userinfo_endpoint": "http://localhost:8080/realms/UCIAP/protocol/openid-connect/userinfo",
  "end_session_endpoint": "http://localhost:8080/realms/UCIAP/protocol/openid-connect/logout",
  "jwks_uri": "http://localhost:8080/realms/UCIAP/protocol/openid-connect/certs"
}
````

---

## 🔑 Supported OAuth 2.0 / OIDC Flows

| Flow                      | Supported                  |
| ------------------------- | -------------------------- |
| Authorization Code        | ✅                          |
| Authorization Code + PKCE | ✅                          |
| Client Credentials        | ✅                          |
| Refresh Token             | ✅                          |
| Implicit                  | ❌ (intentionally disabled) |

---

## 👥 User Management

* Email verification required before login
* Password policies enforced via Keycloak
* Realm & client roles supported
* MFA using:

  * Google Authenticator
  * Microsoft Authenticator (TOTP)

---

## 🧩 Client Integration Guide (Spring Boot)

### 1️⃣ JWT Role Converter (Keycloak → Spring Security)

```java
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        Map<String, Object> realmAccess =
                (Map<String, Object>) source.getClaims().get("realm_access");

        if (realmAccess == null || realmAccess.isEmpty()) {
            return Collections.emptyList();
        }

        return ((List<String>) realmAccess.get("roles"))
                .stream()
                .map(role -> "ROLE_" + role.toUpperCase())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
```

---

### 2️⃣ Spring Security Configuration (Resource Server)

```java
@Configuration
public class ServeXAuthenticationConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        JwtAuthenticationConverter jwtAuthConverter = new JwtAuthenticationConverter();
        jwtAuthConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        http
            .sessionManagement(sm ->
                sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(Arrays.asList(
                        "http://localhost:5173",
                        "http://localhost:4200",
                        "https://localhost:4200"
                ));
                config.setAllowedMethods(Arrays.asList("GET","POST","PUT","DELETE","OPTIONS"));
                config.setAllowedHeaders(Collections.singletonList("*"));
                config.setAllowCredentials(true);
                return config;
            }))

            .csrf(csrf -> csrf.disable())

            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            )

            .oauth2ResourceServer(oauth ->
                oauth.jwt(jwt ->
                    jwt.jwtAuthenticationConverter(jwtAuthConverter)
                )
            );

        return http.build();
    }
}
```

---

## 🔒 Token Validation

Clients **must validate tokens using JWKs**, not hardcoded secrets.

```text
JWK URL:
http://localhost:8080/realms/UCIAP/protocol/openid-connect/certs
```

---

## 🚀 Architecture Overview

```
Client (React / Angular)
        ↓
OAuth 2.0 Authorization Code + PKCE
        ↓
Keycloak (UCIAP Realm)
        ↓
JWT Access Token
        ↓
Spring Boot / .NET Resource Servers
```

---

## ⚠️ Important Notes (Read This or Regret It)

* Do NOT expose client secrets in frontend apps
* Always use PKCE for browser-based clients
* Implicit Flow is intentionally disabled
* Token introspection is optional — JWT validation is preferred
* MFA is enforced per user or realm policy

---

## 📌 Status

**Production-ready**
Used as the central authentication authority for all UCIAP microservices.

---

## 🧑‍💻 Maintainers

* **Induma Wijesinha**
* **Nawanjana Oshadi**

---

## 📄 License

Internal project – All rights reserved.

```



