package com.b1nd.dodamopenapi.infrastructure.security.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

@Configuration
@EnableWebFluxSecurity
class SecurityConfig {
    @Bean
    protected fun filterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        http
            .httpBasic { it.disable() }
            .formLogin { it.disable() }
            .csrf { it.disable() }
            .cors { corsSpec -> corsSpec.configurationSource(corsConfigurationSource()) }
            .authorizeExchange { it
                .pathMatchers("/").permitAll()
                .pathMatchers("/auth/**").permitAll()
                .pathMatchers(HttpMethod.POST, "/token").permitAll()
                .pathMatchers(HttpMethod.GET, "/app").permitAll()
                .anyExchange().authenticated()
            }
            .addFilterBefore(filterExceptionHandler, SecurityWebFiltersOrder.AUTHENTICATION)
            .addFilterAt(tokenFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build()
    }
}