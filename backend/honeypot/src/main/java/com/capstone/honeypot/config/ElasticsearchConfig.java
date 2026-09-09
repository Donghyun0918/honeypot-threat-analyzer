package com.capstone.honeypot.config;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import co.elastic.clients.transport.rest_client.RestClientTransport;
import org.apache.http.HttpHost;
import org.elasticsearch.client.RestClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;

@Configuration
public class ElasticsearchConfig {

    @Value("${elasticsearch.host:http://elasticsearch:9200}")
    private String esHost;

    @Bean(destroyMethod = "close")
    public RestClient restClient() {
        URI uri = URI.create(esHost);
        int port = uri.getPort() == -1 ? 9200 : uri.getPort();
        return RestClient.builder(new HttpHost(uri.getHost(), port, uri.getScheme())).build();
    }

    @Bean
    public ElasticsearchClient elasticsearchClient(RestClient restClient) {
        return new ElasticsearchClient(new RestClientTransport(restClient, new JacksonJsonpMapper()));
    }
}
