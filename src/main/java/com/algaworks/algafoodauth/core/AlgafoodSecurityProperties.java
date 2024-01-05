package com.algaworks.algafoodauth.core;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Component
@Getter
@Setter
@ConfigurationProperties("algafood.auth")
public class AlgafoodSecurityProperties {


    private String providerUrl;
}
