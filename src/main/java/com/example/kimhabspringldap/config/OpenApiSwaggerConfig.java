package com.example.kimhabspringldap.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiSwaggerConfig {
    @Bean
    public OpenAPI customOpenAPI() {
        final String bearerAuth = "bearerAuth";
        var info = new Info()
                .title("LDAP User")
                .version("1.0").contact(new Contact().name("mr kimhab")
                        .email( "kimhab@mail.mail").url("nomail@gmail.com"))
                .description("This is my api");
        var component = new Components()
                .addSecuritySchemes(bearerAuth, new SecurityScheme()
                        .name(bearerAuth)
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT"));
        var bearer = new OpenAPI()
                .addSecurityItem(new SecurityRequirement().addList(bearerAuth))
                .components(component)
                .info(info);
        return bearer;

    }
}
